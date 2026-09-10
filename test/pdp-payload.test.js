import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildPdpRequest, buildRevaPdpConfigFromEnv, evaluateViaRevaPdp, isRevaPdpConfigured } from "../src/core/pdp.mjs";
import { computeBlockedFlags } from "../src/core/policy.mjs";
import { buildMappingConfigFromEnv } from "../src/core/mapping.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const NOW = Date.parse("2026-06-20T09:00:00Z");

function fixture(name) {
  const p = JSON.parse(fs.readFileSync(path.join(HERE, "..", "examples", "payloads", `${name}.json`), "utf8"));
  // Mirrors normalizeAnalyzePayload() in the handler.
  const pc = { ...(p.plannerContext || {}) };
  if (!Array.isArray(pc.previousToolOutputs) && Array.isArray(pc.previousToolsOutputs)) {
    pc.previousToolOutputs = pc.previousToolsOutputs;
  }
  const inputParameters = Object.entries(p.inputValues || {}).map(([name, value]) => ({ name, value }));
  return { ...p, plannerContext: pc, inputParameters };
}

const FIXTURES = ["microsoft-analyze-allow", "microsoft-analyze-block-tool", "microsoft-analyze-multiturn-drift"];

function build(name, envOverrides = {}) {
  const payload = fixture(name);
  // Go through the real env -> config path, so a test can name an actual variable.
  // `builder` stays as a direct-option escape hatch and wins over anything derived.
  const cfg = buildRevaPdpConfigFromEnv(envOverrides);
  const flags = computeBlockedFlags(payload, { blockedTerms: ["confidential claims", "all policyholders"], blockedToolNames: [] });
  return buildPdpRequest(payload, flags, { principal: {} }, "99999999-9999-9999-9999-999999999999", {
    mapping: cfg.mapping,
    contextAttrPrefix: cfg.contextAttrPrefix,
    sendSchemaContext: cfg.sendSchemaContext,
    environmentMap: cfg.environmentMap,
    sendCopilotContext: cfg.sendCopilotContext,
    includePlannerThought: cfg.includePlannerThought,
    sessionMaxTurns: cfg.sessionMaxTurns,
    sessionMaxChars: cfg.sessionMaxChars,
    nowMs: NOW,
    ...envOverrides.builder
  });
}

// --- the v2 context contract ------------------------------------------------

test("context never carries onBehalfOf — the PDP projects it from principal", () => {
  // Not because it is rejected: probed on pr06 2026-09-10, it is ON the record allowlist and
  // returns 200. It is redundant — it appears in the decision log without us sending it.
  for (const f of FIXTURES) {
    const { body } = build(f);
    assert.equal("onBehalfOf" in body.context, false, `${f}: context.onBehalfOf must not be sent`);
  }
});

test("environment is sent only when mapped, and as the schema's enum string", () => {
  // The store schema declares environment as String PROD | STAGING | DEV | SANDBOX. v1 sent
  // a Record there, which no policy could ever have matched — the shape was the bug, not the
  // key. Copilot only gives an environment GUID, so a mapping has to supply the value.
  const unmapped = build("microsoft-analyze-multiturn-drift").body;
  assert.equal("environment" in unmapped.context, false);

  const mapped = build("microsoft-analyze-multiturn-drift", {
    REVA_ENVIRONMENT_MAP: JSON.stringify({ "55555555-5555-5555-5555-555555555555": "PROD" })
  }).body;
  assert.equal(mapped.context.environment, "PROD");
});

test("context carries only conversation, hops and flat scalars", () => {
  for (const f of FIXTURES) {
    const { body } = build(f);
    for (const [k, v] of Object.entries(body.context)) {
      if (k === "conversation" || k === "hops" || k === "chatHistory") continue;
      assert.ok(
        v === null || ["string", "number", "boolean"].includes(typeof v),
        `${f}: context.${k} must be a flat scalar, got ${typeof v}`
      );
    }
  }
});

test("INVARIANT: conversation and hops are equal in every fixture", () => {
  for (const f of FIXTURES) {
    const { body, shape } = build(f);
    const conv = body.context.conversation?.messages?.length ?? 0;
    const hops = body.context.hops?.length ?? 0;
    assert.equal(conv, hops, `${f}: ${conv} conversation vs ${hops} hops`);
    assert.equal(shape.conversation, shape.hops);
  }
});

// --- transmission -----------------------------------------------------------

test("transmission.role is agent on every tool hop", () => {
  // This webhook only ever sees agent -> tool. Saying "user" tells the evaluator a human
  // asked for whatever the agent decided, and a user instruction SETS intent rather than
  // being measured against it — so ALIGNED becomes correct however far the agent wandered.
  for (const f of FIXTURES) {
    const { body } = build(f);
    assert.equal(body.transmission.role, "agent", f);
    assert.equal(body.subject.type, "Agent", f);
  }
});

test("transmission.content describes the hop, not the user's prompt", () => {
  for (const f of FIXTURES) {
    const payload = fixture(f);
    const { body } = build(f);
    assert.notEqual(body.transmission.content, payload.plannerContext.userMessage, `${f}: hop compared against itself`);
  }
});

test("transmission.content names the tool and its arguments", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  assert.ok(body.transmission.content.startsWith("Send notification email to all-policyholders@internal"));
});

// --- entry hop --------------------------------------------------------------

test("a turn with nothing prior sends conversation and hops for the user ask only", () => {
  const { body, shape } = build("microsoft-analyze-allow");
  assert.equal(shape.conversation, 1);
  assert.equal(body.context.hops[0].action, "invokeAgent");
  assert.equal(body.context.hops[0].subject.type, "User");
});

// --- session ----------------------------------------------------------------

test("session omits messages on turn 1 and includes them from turn 2", () => {
  const first = build("microsoft-analyze-allow").body;
  assert.equal(first.session.turn, 1);
  assert.equal("messages" in first.session, false);

  const later = build("microsoft-analyze-multiturn-drift").body;
  assert.equal(later.session.turn, 3);
  assert.equal(later.session.messages.length, 2);
});

test("session.turn is >= 2 whenever messages are present", () => {
  for (const f of FIXTURES) {
    const { body } = build(f);
    if (body.session.messages?.length) assert.ok(body.session.turn >= 2, f);
  }
});

test("session.startedAt never postdates the first history entry", () => {
  for (const f of FIXTURES) {
    const { body } = build(f);
    const first = body.session.messages?.[0]?.request?.timestamp;
    if (first) assert.ok(Date.parse(body.session.startedAt) <= Date.parse(first), f);
  }
});

test("session.startedAt is the chat's start, not this turn's", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  // The seed greeting is dropped as content but is exactly when the chat began.
  assert.equal(body.session.startedAt, "2026-06-20T07:48:58Z");
});

test("session.id comes from the conversation, so a chat shares one thread", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  assert.equal(body.session.id, "66666666-6666-6666-6666-666666666666");
});

// --- gateway messages -------------------------------------------------------

test("our own block text is replaced, so the blocked term is not re-injected", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  const serialized = JSON.stringify(body);
  assert.ok(serialized.includes("[reva-gateway]"), "marker present");
  // The user's own words legitimately contain the phrase; our enforcement prose must not.
  const gatewayResponses = body.session.messages.map((m) => m.response?.content || "").join(" ");
  assert.ok(!gatewayResponses.includes("confidential claims"));
  assert.ok(!serialized.includes("Reva Trust Gateway"));
});

test("the refusal stays visible so asked -> refused -> reworded is legible", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  assert.equal(body.session.messages[1].response.content, "[reva-gateway] The previous request was blocked by policy.");
  assert.ok(body.session.messages[1].request.content.includes("external-partner@gmail.com"));
});

// --- entity mapping ---------------------------------------------------------

test("explicit maps drive subject, resource and principal", () => {
  const { body, resolutions } = build("microsoft-analyze-multiturn-drift", {
    REVA_PRINCIPAL_ID_MAP: JSON.stringify({ "22222222-2222-2222-2222-222222222222": "alice" }),
    REVA_AGENT_ID_MAP: JSON.stringify({ "33333333-3333-3333-3333-333333333333": "underwriter-copilot" }),
    REVA_TOOL_ID_MAP: JSON.stringify({
      "pub_UnderwriterCopilot.action.UnderwriterCopilotTools-UnderwriterCopilotTools_nAl": "send-notification-email",
      "pub_UnderwriterCopilot.action.UnderwriterCopilotTools-UnderwriterCopilotTools_ctk": "fetch-risk-score"
    })
  });
  assert.equal(body.principal.id, "alice");
  assert.equal(body.subject.id, "underwriter-copilot");
  assert.equal(body.resource.id, "send-notification-email");
  assert.equal(resolutions.tool.via, "id-map");
});

test("past tool hops go through the same mapping as the current one", () => {
  const { body } = build("microsoft-analyze-multiturn-drift", {
    REVA_TOOL_ID_MAP: JSON.stringify({
      "pub_UnderwriterCopilot.action.UnderwriterCopilotTools-UnderwriterCopilotTools_nAl": "send-notification-email"
    })
  });
  const toolHops = body.context.hops.filter((h) => h.action === "invokeTool");
  for (const h of toolHops) assert.ok(h.resource.id && !h.resource.id.includes("pub_"), h.resource.id);
});

test("principal is the end user, never the agent", () => {
  for (const f of FIXTURES) {
    const { body } = build(f);
    assert.equal(body.principal.type, "User", f);
  }
});

// --- context flags ----------------------------------------------------------

test("the blocked-term flags are no longer sent", () => {
  // Removed deliberately: no policy referenced them, and they were never declared in the
  // store schema. They are still COMPUTED — the observability event records them, and the
  // no-PDP fallback path still enforces BLOCKED_TERMS locally — just not sent as context.
  const { body } = build("microsoft-analyze-multiturn-drift");
  for (const k of [
    "blockedTermInUserMessage",
    "blockedTermInInput",
    "isBlockedTool",
    "blockedTermInPreviousOutput"
  ]) {
    assert.equal(k in body.context, false, `${k} must not be sent`);
  }
});

test("the prefix applies to OUR attributes and not to the schema's own", () => {
  // The store namespaces attributes an operator ADDS. Prefixing `timestamp` or `sourceIp`
  // would invent a key nobody declared, and the declared one would then be missing.
  const { body } = build("microsoft-analyze-multiturn-drift", {
    REVA_CONTEXT_ATTR_PREFIX: "MyPolicyStore_"
  });
  assert.equal(body.context["MyPolicyStore_channelId"], "pva-studio");
  assert.equal(body.context.channelId, undefined);

  assert.equal(typeof body.context.timestamp, "number");
  assert.equal(body.context["MyPolicyStore_timestamp"], undefined);
});

test("no fixture can emit a session turn the PDP would reject", () => {
  // A contract guard, not a scenario: the API refuses the whole request over any prior turn
  // missing response.content, so this must hold for every payload we can build.
  for (const name of ["microsoft-analyze-allow", "microsoft-analyze-block-tool", "microsoft-analyze-multiturn-drift"]) {
    const { body } = build(name);
    for (const m of body.session.messages || []) {
      assert.ok(m.response, `${name} turn ${m.turn}: response is required`);
      assert.notEqual(m.response.content, "", `${name} turn ${m.turn}: response.content is required`);
    }
  }
});

// --- open-policy inputs (E3 / E4) -------------------------------------------

test("Copilot metadata an open policy can test travels as flat context scalars", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  assert.equal(body.context.tenantId, "11111111-1111-1111-1111-111111111111");
  assert.equal(body.context.channelId, "pva-studio");
  assert.equal(body.context.agentEnvironmentId, "55555555-5555-5555-5555-555555555555");
  assert.equal(body.context.agentIsPublished, false); // false must survive, not be dropped
  // Records are refused by the API, so every one of these has to be a scalar.
  for (const v of Object.values(body.context)) {
    const isRecord = v !== null && typeof v === "object" && !Array.isArray(v);
    if (isRecord) assert.ok(["conversation", "hops"].some((k) => body.context[k] === v));
  }
});

test("Microsoft's tool type is NOT sent as `toolType`", () => {
  // The schema already has Tool.toolType as an entity attribute, enum MCP | OPENAPI | ...
  // Microsoft's is a different concept with a disjoint value space, so it gets its own name
  // rather than shadowing a declared one.
  const { body } = build("microsoft-analyze-allow");
  assert.equal(body.context.toolType, undefined);
  assert.equal(body.context.copilotToolType, "CustomConnectorToolDefinition");
});

test("the schema's own context attributes are sent under their declared names", () => {
  const { body } = build("microsoft-analyze-multiturn-drift");
  // Long, and declared required. Reva checks `required` when ingesting entity data rather
  // than when evaluating, so this is correctness rather than a precondition.
  assert.equal(body.context.timestamp, NOW);
  assert.equal(body.context.sourceIp, "2001:db8::1");
});

test("REVA_SEND_SCHEMA_CONTEXT=false drops them", () => {
  const { body } = build("microsoft-analyze-multiturn-drift", { REVA_SEND_SCHEMA_CONTEXT: "false" });
  assert.equal("timestamp" in body.context, false);
  assert.equal("sourceIp" in body.context, false);
});

test("REVA_SEND_COPILOT_CONTEXT=false restores the previous payload", () => {
  const { body } = build("microsoft-analyze-multiturn-drift", { REVA_SEND_COPILOT_CONTEXT: "false" });
  assert.equal(body.context.channelId, undefined);
  assert.equal(body.context.tenantId, undefined);
});

test("no entities key at all when no groups are configured", () => {
  // The payload must be byte-identical to before this feature existed.
  const { body } = build("microsoft-analyze-allow");
  assert.equal("entities" in body, false);
});

test("configured groups become Cedar UserGroup parents", () => {
  // Lets a policy say `principal in UserGroup::"Underwriters"` without registering the user.
  const { body } = build("microsoft-analyze-multiturn-drift", {
    REVA_USER_GROUPS_MAP: JSON.stringify({ "22222222-2222-2222-2222-222222222222": ["Underwriters", "EndUser"] })
  });
  assert.deepEqual(body.entities, [
    {
      uid: { type: "User", id: "22222222-2222-2222-2222-222222222222" },
      parents: [
        { type: "UserGroup", id: "Underwriters" },
        { type: "UserGroup", id: "EndUser" }
      ]
    }
  ]);
});

test("groups can be keyed by the resolved Reva id as well as the raw Microsoft one", () => {
  const { body } = build("microsoft-analyze-multiturn-drift", {
    REVA_PRINCIPAL_ID_MAP: JSON.stringify({ "22222222-2222-2222-2222-222222222222": "alice" }),
    REVA_USER_GROUPS_MAP: JSON.stringify({ alice: ["Underwriters"] })
  });
  assert.equal(body.entities[0].uid.id, "alice");
  assert.deepEqual(body.entities[0].parents, [{ type: "UserGroup", id: "Underwriters" }]);
});

// --- transport --------------------------------------------------------------

function stubFetch(impl) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return () => {
    globalThis.fetch = original;
  };
}

const PDP_CONFIG = buildRevaPdpConfigFromEnv({
  REVA_PDP_URL: "https://pdp.example/pdp/v2/ai/evaluation",
  REVA_POLICY_STORE_ID: "store-1",
  REVA_PDP_TOKEN: "tok",
  REVA_PDP_TIMEOUT_MS: "80"
});

test("isRevaPdpConfigured requires url, store and token", () => {
  assert.equal(isRevaPdpConfigured(PDP_CONFIG), true);
  assert.equal(isRevaPdpConfigured({ ...PDP_CONFIG, pdpToken: "" }), false);
});

test("a 403 carrying a decision is a policy DENY, not a transport failure", async () => {
  const restore = stubFetch(async () => new Response(
    JSON.stringify({ decision: false, error_type: "POLICY_DENIED", context: { reason: "denied" } }),
    { status: 403 }
  ));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, true);
    assert.equal(out.policyResult.blockAction, true);
  } finally {
    restore();
  }
});

test("a 200 with decision true allows", async () => {
  const restore = stubFetch(async () => new Response(JSON.stringify({ decision: true, threadId: "t" }), { status: 200 }));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, true);
    assert.equal(out.policyResult.blockAction, false);
  } finally {
    restore();
  }
});

// The live body below is verbatim from pr06 on 2026-09-10, sending a session whose first
// prior turn had no response. The API rejects a malformed request with 400 AND decision:false,
// so "carries a decision" is not sufficient to make it a decision — only the status is.
test("a 400 carrying decision:false is a MALFORMED REQUEST, not a policy deny", async () => {
  const restore = stubFetch(async () => new Response(
    JSON.stringify({ decision: false, context: { reason: "invalid session: session.messages[0].response is required" } }),
    { status: 400 }
  ));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, false, "must not be reported as an authoritative decision");
    assert.equal(out.policyResult, null);
    assert.equal(out.diagnostics.errorKind, "invalid-payload");
    // The PDP's own words are kept, because this is our bug and the reason names it.
    assert.match(out.diagnostics.error, /invalid session/);
    assert.equal(out.diagnostics.httpStatus, 400);
  } finally {
    restore();
  }
});

test("a 403 WITHOUT error_type is our payload being wrong, not a policy deny", async () => {
  // pr06 verbatim (2026-09-10) for a resource type the action does not take. It carries
  // decision:false and a 403 exactly like a real denial, and is not one — only POLICY_DENIED
  // separates them. Reading this as a deny is what sends someone into Cedar for an hour.
  const restore = stubFetch(async () => new Response(
    JSON.stringify({
      decision: false,
      context: { reason: "resource entity is incompatible with action: entity action mismatch: invokeTool requires a Tool resource, resolved \"Widget\"" }
    }),
    { status: 403 }
  ));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, false, "must not be reported as an authoritative decision");
    assert.equal(out.policyResult, null);
    assert.equal(out.diagnostics.errorKind, "invalid-payload");
    assert.match(out.diagnostics.error, /entity action mismatch/);
  } finally {
    restore();
  }
});

test("a 5xx carrying a decision is a service fault, not a policy deny", async () => {
  const restore = stubFetch(async () => new Response(JSON.stringify({ decision: false }), { status: 503 }));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, false);
    assert.equal(out.diagnostics.errorKind, "protocol");
  } finally {
    restore();
  }
});

// --- principal provenance (C) -----------------------------------------------

test("the end user comes from the body, never from the transport token", () => {
  // The bearer token authenticates Power Platform, not the person who typed. Under the
  // production federated credential its oid is a service principal, so preferring it would
  // authorize the wrong subject entirely.
  const p = fixture("microsoft-analyze-allow");
  const built = buildPdpRequest(
    p, {}, { principal: { oid: "SERVICE-PRINCIPAL-OID", sub: "sp-sub" } }, "cid",
    { mapping: buildMappingConfigFromEnv({}), nowMs: NOW }
  );
  assert.equal(built.principalSource, "conversation-metadata");
  assert.notEqual(built.body.principal.id, "SERVICE-PRINCIPAL-OID");
});

test("a missing body user falls back to the token, and says so", () => {
  const p = fixture("microsoft-analyze-allow");
  delete p.conversationMetadata.user;
  const built = buildPdpRequest(
    p, {}, { principal: { oid: "SERVICE-PRINCIPAL-OID" } }, "cid",
    { mapping: buildMappingConfigFromEnv({}), nowMs: NOW }
  );
  assert.equal(built.principalSource, "token-oid");
});

test("REVA_REQUIRE_BODY_PRINCIPAL refuses BEFORE the call when the user is not in the body", async () => {
  const cfg = buildRevaPdpConfigFromEnv({
    REVA_PDP_URL: "https://pdp.example/pdp/v2/ai/evaluation",
    REVA_POLICY_STORE_ID: "store-1",
    REVA_PDP_TOKEN: "tok",
    REVA_REQUIRE_BODY_PRINCIPAL: "true"
  });
  const p = fixture("microsoft-analyze-allow");
  delete p.conversationMetadata.user;
  let called = false;
  const restore = stubFetch(async () => { called = true; return new Response("{}", { status: 200 }); });
  try {
    const out = await evaluateViaRevaPdp(p, {}, cfg, { principal: { oid: "sp" } }, "cid");
    assert.equal(called, false, "must refuse without asking the PDP");
    assert.equal(out.ok, false);
    assert.equal(out.diagnostics.errorKind, "no-principal");
  } finally {
    restore();
  }
});

test("principal provenance is on every event's entityResolution", async () => {
  const restore = stubFetch(async () => new Response(JSON.stringify({ decision: true }), { status: 200 }));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.match(out.diagnostics.entityResolution.user, /^conversation-metadata:/);
  } finally {
    restore();
  }
});

// --- retry (D) --------------------------------------------------------------

function socketError(code) {
  const err = new TypeError("fetch failed");
  err.cause = Object.assign(new Error("socket hang up"), { code });
  return err;
}

test("a socket that dies mid-flight is retried once and can succeed", async () => {
  let calls = 0;
  const restore = stubFetch(async () => {
    calls += 1;
    if (calls === 1) throw socketError("ECONNRESET");
    return new Response(JSON.stringify({ decision: true }), { status: 200 });
  });
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(calls, 2);
    assert.equal(out.ok, true);
    assert.equal(out.policyResult.blockAction, false);
    assert.equal(out.diagnostics.attempts, 2);
    assert.equal(out.diagnostics.retriedAfter, "ECONNRESET");
  } finally {
    restore();
  }
});

test("the retry happens at most once", async () => {
  let calls = 0;
  const restore = stubFetch(async () => { calls += 1; throw socketError("ECONNRESET"); });
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(calls, 2, "two attempts total, never a third");
    assert.equal(out.ok, false);
    assert.equal(out.diagnostics.errorKind, "transport");
  } finally {
    restore();
  }
});

test("a refused connection is NOT retried — the service is down, not flaky", async () => {
  let calls = 0;
  const restore = stubFetch(async () => { calls += 1; throw socketError("ECONNREFUSED"); });
  try {
    await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(calls, 1);
  } finally {
    restore();
  }
});

test("retrying never exceeds the single deadline shared by both attempts", async () => {
  // Microsoft fails OPEN past its own budget, so two attempts must not cost 2x timeoutMs.
  const started = Date.now();
  let calls = 0;
  const restore = stubFetch(async (_u, init) => {
    calls += 1;
    if (calls === 1) throw socketError("ECONNRESET");
    return new Promise((_res, rej) => {
      init.signal.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" })));
    });
  });
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    const elapsed = Date.now() - started;
    assert.equal(out.diagnostics.errorKind, "timeout");
    // PDP_CONFIG sets 80ms. A per-attempt clock would allow ~160ms.
    assert.ok(elapsed < 140, `two attempts took ${elapsed}ms, which exceeds the shared budget`);
  } finally {
    restore();
  }
});

test("a 401 with no decision is an auth fault, not a deny", async () => {
  // A v1 token against v2 lands here. It must not read as "blocked by policy".
  const restore = stubFetch(async () => new Response("unauthorized", { status: 401 }));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, false);
    assert.equal(out.diagnostics.errorKind, "auth");
  } finally {
    restore();
  }
});

test("a slow PDP aborts and is reported as a timeout", async () => {
  const restore = stubFetch(
    (_url, init) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => resolve(new Response("{}", { status: 200 })), 5000);
        init.signal.addEventListener("abort", () => {
          clearTimeout(t);
          const e = new Error("aborted");
          e.name = "AbortError";
          reject(e);
        });
      })
  );
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.ok, false);
    assert.equal(out.diagnostics.errorKind, "timeout");
    assert.ok(out.diagnostics.error.includes("timed out"));
  } finally {
    restore();
  }
});

test("unmapped entities reach the PDP instead of being refused locally", async () => {
  // The store no longer has to know an entity in advance: ids are free-form and open
  // policies match on type and condition. Refusing here blocked calls pr06 allows.
  let called = false;
  const restore = stubFetch(async () => {
    called = true;
    return new Response(JSON.stringify({ decision: true }), { status: 200 });
  });
  try {
    const cfg = buildRevaPdpConfigFromEnv({
      REVA_PDP_URL: "https://pdp.example/pdp/v2/ai/evaluation",
      REVA_POLICY_STORE_ID: "s",
      REVA_PDP_TOKEN: "t",
      REVA_ON_UNMAPPED_ENTITY: "deny" // removed; must have no effect
    });
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-allow"), {}, cfg, { principal: {} }, "cid");
    assert.equal(called, true, "the request must reach the PDP");
    assert.equal(out.ok, true);
    assert.equal(out.policyResult.blockAction, false);
    // Still visible: the event records that the tool resolved by slug, not by a map.
    assert.match(out.diagnostics.entityResolution.tool, /^slug:/);
  } finally {
    restore();
  }
});

test("context carries no record outside the API's allowlist", () => {
  // Probed one key at a time against pr06 (2026-09-10): environment and onBehalfOf are
  // ACCEPTED, contrary to an earlier claim in this file; any other record is a 400 naming
  // the key. We send neither, because both are inert, but the payload must never grow a
  // record of its own — that is the failure mode this guards.
  const ALLOWED_RECORDS = new Set(["conversation", "hops", "chatHistory"]);
  for (const name of ["microsoft-analyze-allow", "microsoft-analyze-multiturn-drift"]) {
    const { body } = build(name);
    for (const [key, value] of Object.entries(body.context)) {
      const isRecord = value !== null && typeof value === "object" && !Array.isArray(value);
      if (isRecord) {
        assert.ok(ALLOWED_RECORDS.has(key), `context.${key} is a record the API would reject`);
      }
    }
  }
});

test("the traceparent header ties every decision in a chat to one trace", async () => {
  let seen = null;
  const restore = stubFetch(async (_url, init) => {
    seen = init.headers;
    return new Response(JSON.stringify({ decision: true }), { status: 200 });
  });
  try {
    await evaluateViaRevaPdp(fixture("microsoft-analyze-multiturn-drift"), {}, PDP_CONFIG, { principal: {} }, "99999999-9999-9999-9999-999999999999");
    assert.match(seen.traceparent, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    assert.equal(seen.policyStoreId, "store-1");
    assert.equal(seen.Authorization, "Bearer tok");
  } finally {
    restore();
  }
});

test("diagnostics report payload shape and entity resolution, never prompt text", async () => {
  const restore = stubFetch(async () => new Response(JSON.stringify({ decision: true }), { status: 200 }));
  try {
    const out = await evaluateViaRevaPdp(fixture("microsoft-analyze-multiturn-drift"), {}, PDP_CONFIG, { principal: {} }, "cid");
    assert.equal(out.diagnostics.payloadShape.conversation, out.diagnostics.payloadShape.hops);
    assert.ok(out.diagnostics.entityResolution.tool.startsWith("slug:"));
    assert.ok(!JSON.stringify(out.diagnostics.payloadShape).includes("policyholders"));
  } finally {
    restore();
  }
});
