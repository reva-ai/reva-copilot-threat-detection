import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { clearObservabilityEvents, listObservabilityEvents, getPolicyConfig } from "../src/storage/index.mjs";
import { __reset as resetMemoryStore } from "../src/storage/memory.mjs";

/**
 * Where the time went, and what stopped being spent.
 *
 * A live event showed totalMs 3961 against a PDP leg of 678ms, and nothing in the record
 * could say where the other 3.3 seconds had gone — only the PDP call was ever timed. These
 * cover the phase breakdown that answers that, and the work removed from the hot path while
 * looking into it.
 */
let seq = 0;
async function loadRoute(env = {}) {
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await import(new URL(`../src/routes/analyze-tool-execution.mjs?v=${++seq}`, import.meta.url).href);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const PDP_ENV = {
  ALLOW_INSECURE_LOCAL_AUTH: "true",
  AUTH_TOKEN: "dev-token",
  REVA_PDP_URL: "https://pdp.example/pdp/v2/ai/evaluation",
  REVA_POLICY_STORE_ID: "store-1",
  REVA_PDP_TOKEN: "tok",
  REVA_PDP_TIMEOUT_MS: "500"
};

const PAYLOAD = {
  plannerContext: { userMessage: "Look up the balance", thought: "lookup", chatHistory: [], previousToolOutputs: [] },
  toolDefinition: { id: "tool-1", type: "ToolDefinition", name: "Lookup-Balance", description: "Reads a balance." },
  inputValues: { account: "A-1" },
  conversationMetadata: {
    agent: { id: "agent-1", tenantId: "t", environmentId: "e", isPublished: true },
    user: { id: "user-1", tenantId: "t" },
    conversationId: "conv-1"
  }
};

const request = (over = {}) => ({
  method: "POST",
  path: "/analyze-tool-execution",
  headers: { authorization: "Bearer dev-token", "content-type": "application/json", "x-ms-correlation-id": "cid-1" },
  body: JSON.stringify(PAYLOAD),
  ...over
});

function stubFetch(impl) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return () => {
    globalThis.fetch = original;
  };
}

const ALLOW = async () => new Response(JSON.stringify({ decision: true }), { status: 200 });

// ── phase timings ───────────────────────────────────────────────────────────

test("the event breaks the response time into phases", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(request());
    const [{ latency }] = await listObservabilityEvents(10);
    for (const field of ["serverTotalMs", "authMs", "pdpMs", "otherMs"]) {
      assert.equal(typeof latency[field], "number", `${field} must be recorded`);
      assert.ok(latency[field] >= 0, `${field} must not be negative, got ${latency[field]}`);
    }
    // NOT asserted: that the phases sum to the total. otherMs is DERIVED as the remainder,
    // so that sum is an identity — it holds even when a phase is mismeasured, which makes it
    // look like a guard while guarding nothing.
    assert.equal(latency.budgetMs, 1000);
  } finally {
    restore();
  }
});

test("coldStart is true for the first request on a container and false after", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(request());
    await handleAnalyzeToolExecution(request());
    const events = await listObservabilityEvents(10); // newest first
    assert.equal(events[1].latency.coldStart, true, "the first invocation is a cold start");
    assert.equal(events[0].latency.coldStart, false, "the second is not");
  } finally {
    restore();
  }
});

test("a slow PDP shows up as pdpMs, cross-checked against the client's own measurement", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(async () => {
    await new Promise((r) => setTimeout(r, 120));
    return new Response(JSON.stringify({ decision: true }), { status: 200 });
  });
  try {
    await handleAnalyzeToolExecution(request());
    const [only] = await listObservabilityEvents(10);
    assert.ok(only.latency.pdpMs >= 100, `the PDP leg should own the delay, got ${only.latency.pdpMs}`);
    assert.equal(only.latency.pdpMs, only.pdp.latencyMs, "the two measurements must not drift apart");
  } finally {
    restore();
  }
});

// ── the work removed from the hot path ──────────────────────────────────────

test("with the PDP configured, the policy config is never read", async () => {
  // The saving itself: a storage round trip per request (a DynamoDB GetItem in a real
  // deployment) feeding nothing but a diagnostic no policy and no dashboard consumed.
  //
  // Proven without instrumenting production code. getPolicyConfig seeds the row from the
  // environment on first read, so after a reset the row is unseeded — and if the request
  // never reads it, a value put into the environment AFTERWARDS is still the one that gets
  // seeded. If the request had read it, the row would already be fixed and the later value
  // ignored.
  await clearObservabilityEvents();
  resetMemoryStore();
  const savedTerm = process.env.BLOCKED_TOOL_NAMES;
  delete process.env.BLOCKED_TOOL_NAMES;

  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(request());

    process.env.BLOCKED_TOOL_NAMES = "seeded-after-the-request";
    const row = await getPolicyConfig();
    assert.deepEqual(
      row.blockedToolNames,
      ["seeded-after-the-request"],
      "the row was already seeded, so the PDP path read the policy config"
    );
  } finally {
    restore();
    if (savedTerm === undefined) delete process.env.BLOCKED_TOOL_NAMES;
    else process.env.BLOCKED_TOOL_NAMES = savedTerm;
    resetMemoryStore();
  }
});

test("the removed flags are gone from the event, not merely emptied", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(request());
    const [only] = await listObservabilityEvents(10);
    assert.equal("computedFlags" in only.pdp, false, "an empty object would still cost a write");
  } finally {
    restore();
  }
});

test("without a PDP, the configured terms still read and still block", async () => {
  // The one path where the terms ever had authority. Removing them from the PDP path must
  // not disarm the fallback.
  await clearObservabilityEvents();
  resetMemoryStore();
  const saved = process.env.BLOCKED_TOOL_NAMES;
  process.env.BLOCKED_TOOL_NAMES = "Lookup-Balance";
  try {
    const { handleAnalyzeToolExecution } = await loadRoute({
      ALLOW_INSECURE_LOCAL_AUTH: "true",
      AUTH_TOKEN: "dev-token",
      REVA_PDP_URL: undefined,
      REVA_POLICY_STORE_ID: undefined,
      REVA_PDP_TOKEN: undefined
    });
    const res = await handleAnalyzeToolExecution(request());
    assert.equal(JSON.parse(res.body).blockAction, true, "the fallback must still enforce its terms");
  } finally {
    if (saved === undefined) delete process.env.BLOCKED_TOOL_NAMES;
    else process.env.BLOCKED_TOOL_NAMES = saved;
    resetMemoryStore();
  }
});

// ── the JWKS fetch, which is the thing actually suspected ───────────────────
//
// Under ALLOW_INSECURE_LOCAL_AUTH the auth phase is a string comparison and authMs is
// always ~0, so nothing above shows it measuring anything. The phase only matters in entra
// mode, where a cold cache means an outbound call to Microsoft on the critical path.

const TENANT = "11111111-1111-1111-1111-111111111111";
const AUDIENCE = "https://threatdetection.example.com";
const CALLER_APP = "22222222-2222-2222-2222-222222222222";

/** One keypair for the file — eight RSA keygens per run is what made security.test.js flaky. */
const KEYPAIR = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function signedToken() {
  const { publicKey, privateKey } = KEYPAIR;
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-kid", use: "sig", alg: "RS256" };
  const now = Math.floor(Date.now() / 1000);
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signingInput = `${b64({ alg: "RS256", typ: "JWT", kid: "test-kid" })}.${b64({
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    tid: TENANT,
    aud: AUDIENCE,
    appid: CALLER_APP,
    exp: now + 600,
    nbf: now - 60
  })}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return { token: `${signingInput}.${signer.sign(privateKey).toString("base64url")}`, jwk };
}

test("a cold JWKS cache is recorded, and shows up in authMs", async () => {
  await clearObservabilityEvents();
  const { token, jwk } = signedToken();
  const { handleAnalyzeToolExecution } = await loadRoute({
    ...PDP_ENV,
    ALLOW_INSECURE_LOCAL_AUTH: undefined,
    AUTH_TOKEN: undefined,
    ENTRA_TENANT_ID: TENANT,
    ENTRA_AUDIENCE: AUDIENCE,
    ENTRA_ALLOWED_APP_IDS: CALLER_APP
  });

  const JWKS_DELAY_MS = 120;
  let jwksCalls = 0;
  const restore = stubFetch(async (url) => {
    if (String(url).includes("login.microsoftonline.com")) {
      jwksCalls += 1;
      await new Promise((r) => setTimeout(r, JWKS_DELAY_MS));
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    }
    return new Response(JSON.stringify({ decision: true }), { status: 200 });
  });

  const withToken = () => request({ headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "x-ms-correlation-id": "cid-1" } });

  try {
    await handleAnalyzeToolExecution(withToken());
    await handleAnalyzeToolExecution(withToken());
    const [second, first] = await listObservabilityEvents(10); // newest first

    assert.equal(jwksCalls, 1, "the second request must be served from the cache");
    assert.equal(first.latency.jwksFetched, true, "the cold request fetched the keys");
    assert.equal(second.latency.jwksFetched, false, "the warm one did not");
    assert.ok(
      first.latency.authMs >= JWKS_DELAY_MS,
      `cold authMs should include the ${JWKS_DELAY_MS}ms fetch, got ${first.latency.authMs}`
    );
    assert.ok(
      second.latency.authMs < first.latency.authMs,
      `warm authMs (${second.latency.authMs}) should be below cold (${first.latency.authMs})`
    );
  } finally {
    restore();
  }
});

// ── the host's clock ────────────────────────────────────────────────────────
//
// serverTotalMs starts inside the route, so it misses cold-start module init and any
// queueing ahead of it — both firmly inside the deadline Copilot is measuring against. The
// adapter supplies receivedAtMs, which recovers them.
//
// None of this closes the real gap: the client-to-host network is still invisible, and on a
// deployment far from the Power Platform region it is the larger half. These tests exist so
// the number stops *claiming* otherwise.

const receivedAgo = (agoMs) => request({ receivedAtMs: Date.now() - agoMs });

test("gatewayMs measures from when the host received the request", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(receivedAgo(400));
    const [{ latency }] = await listObservabilityEvents(10);
    assert.ok(latency.gatewayMs >= 400, `gatewayMs should include the 400ms before us, got ${latency.gatewayMs}`);
    assert.ok(
      latency.gatewayMs > latency.serverTotalMs,
      `gatewayMs (${latency.gatewayMs}) must exceed serverTotalMs (${latency.serverTotalMs})`
    );
  } finally {
    restore();
  }
});

test("the budget is judged on the host clock, not the route's", async () => {
  // The whole point. Time spent before the route was invisible, so a request that blew the
  // budget in a queue or in cold-start init reported budgetExceeded: false.
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(receivedAgo(1500));
    const [{ latency }] = await listObservabilityEvents(10);
    assert.ok(latency.serverTotalMs < 1000, "the route itself was fast");
    assert.equal(latency.serverBudgetExceeded, true, "but the request as a whole was not");
  } finally {
    restore();
  }
});

test("with no stamp, gatewayMs is null and the budget falls back to the route", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(request()); // no receivedAtMs
    const [{ latency }] = await listObservabilityEvents(10);
    assert.equal(latency.gatewayMs, null);
    assert.equal(latency.serverBudgetExceeded, latency.serverTotalMs > 1000);
  } finally {
    restore();
  }
});

test("clock skew is reported as null, never as a negative duration", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(receivedAgo(-5000)); // host clock 5s ahead
    const [{ latency }] = await listObservabilityEvents(10);
    assert.equal(latency.gatewayMs, null);
  } finally {
    restore();
  }
});

test("a non-numeric stamp does not produce NaN", async () => {
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(PDP_ENV);
  const restore = stubFetch(ALLOW);
  try {
    await handleAnalyzeToolExecution(request({ receivedAtMs: "not-a-number" }));
    const [{ latency }] = await listObservabilityEvents(10);
    assert.equal(latency.gatewayMs, null);
    assert.equal(Number.isNaN(latency.gatewayMs), false);
  } finally {
    restore();
  }
});
