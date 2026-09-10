import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createAuth, buildAuthConfigFromEnv, callerAppIdOf } from "../src/core/auth.mjs";
import { redactAnalyzePayload, redactForStorage, REDACTED } from "../src/core/redact.mjs";

// ── caller authorization ────────────────────────────────────────────────────
//
// Microsoft leaves this to the partner: "you need to implement authorization logic and
// validate incoming tokens ... for example, using an allow list of app IDs". Tenant and
// audience alone let any app in the customer's tenant drive the webhook.

const TENANT = "11111111-1111-1111-1111-111111111111";
const AUDIENCE = "https://threatdetection.example.com";
const POWER_PLATFORM = "22222222-2222-2222-2222-222222222222";
const OTHER_APP = "33333333-3333-3333-3333-333333333333";

/** A real RS256 token, signed with a throwaway key whose JWK we hand to the verifier. */
/**
 * One keypair for the whole file.
 *
 * This used to generate a fresh RSA-2048 key inside signedToken(), which is eight keygens
 * per run — and `node --test` runs test files as parallel processes, so those eight land on
 * a machine already saturated by every other file. Under that contention this file
 * intermittently died with SIGABRT rather than failing an assertion: roughly 1 run in 20,
 * enough to redden CI on an unrelated pull request and send someone hunting a bug that is
 * not there.
 *
 * Nothing needed distinct keys. Each test builds its own verifier and hands it the matching
 * JWK, so one keypair is as good as eight and costs an eighth of the CPU.
 */
const KEYPAIR = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

function signedToken(claims) {
  const { publicKey, privateKey } = KEYPAIR;
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-kid", use: "sig", alg: "RS256" };
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: "test-kid" };
  const payload = {
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    tid: TENANT,
    aud: AUDIENCE,
    exp: now + 600,
    nbf: now - 60,
    ...claims
  };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const sig = signer.sign(privateKey).toString("base64url");
  return { token: `${signingInput}.${sig}`, jwk };
}

function authWith(claims, allowedAppIds) {
  const { token, jwk } = signedToken(claims);
  const auth = createAuth({
    mode: "entra",
    tenantId: TENANT,
    audience: AUDIENCE,
    allowedAppIds,
    jwks: [jwk] // bypass the JWKS fetch
  });
  return { auth, token };
}

test("callerAppIdOf reads appid (v1 tokens) and azp (v2 tokens)", () => {
  assert.equal(callerAppIdOf({ appid: "A" }), "A");
  assert.equal(callerAppIdOf({ azp: "B" }), "B");
  assert.equal(callerAppIdOf({}), null);
  assert.equal(callerAppIdOf({ appid: "   " }), null);
});

test("entra mode refuses to construct without an allowlist", () => {
  // The failure this guards is silent: tenant and audience pass, the service answers
  // normally, and nothing anywhere reports that the application check never ran. It has to
  // be a startup error — a service already serving traffic unprotected has failed.
  assert.throws(
    () => createAuth({ mode: "entra", tenantId: TENANT, audience: AUDIENCE, allowedAppIds: [] }),
    /ENTRA_ALLOWED_APP_IDS is required/
  );
  // Omitted entirely, not merely empty.
  assert.throws(
    () => createAuth({ mode: "entra", tenantId: TENANT, audience: AUDIENCE }),
    /ENTRA_ALLOWED_APP_IDS is required/
  );
});

test("the refusal tells the operator where to find the value", () => {
  // A config error nobody can act on gets worked around instead of fixed. This one names
  // the variable, where the id comes from, and the local-development alternative — without
  // that last part someone reaches for ALLOW_INSECURE_LOCAL_AUTH in production to get past
  // it, turning a good control into a worse outcome than not having it.
  try {
    createAuth({ mode: "entra", tenantId: TENANT, audience: AUDIENCE, allowedAppIds: [] });
    assert.fail("expected a throw");
  } catch (err) {
    assert.match(err.message, /ENTRA_ALLOWED_APP_IDS/);
    assert.match(err.message, /Application \(client\) ID/);
    assert.match(err.message, /ALLOW_INSECURE_LOCAL_AUTH/);
  }
});

test("the caller app id is still recorded, for confirming the configured value", async () => {
  // Recording survives the allowlist becoming mandatory. It is no longer how the id is
  // discovered — Power Platform federates into the customer's own registration, so the
  // value is known from setup — but it is how an operator confirms the two match.
  const { auth, token } = authWith({ appid: POWER_PLATFORM }, [POWER_PLATFORM]);
  const res = await auth.authenticateBearerToken(token);
  assert.equal(res.callerAppId, POWER_PLATFORM);
});

test("with an allowlist, the permitted app is accepted", async () => {
  const { auth, token } = authWith({ appid: POWER_PLATFORM }, [POWER_PLATFORM]);
  const res = await auth.authenticateBearerToken(token);
  assert.equal(res.ok, true);
  assert.equal(res.callerAppId, POWER_PLATFORM);
});

test("with an allowlist, another app in the SAME tenant is rejected", async () => {
  // The whole point: a valid, correctly-audienced, same-tenant token that is not Copilot.
  const { auth, token } = authWith({ appid: OTHER_APP }, [POWER_PLATFORM]);
  await assert.rejects(() => auth.authenticateBearerToken(token), /not in ENTRA_ALLOWED_APP_IDS/);
});

test("app id comparison is case-insensitive, as Entra GUIDs are", async () => {
  const { auth, token } = authWith({ appid: POWER_PLATFORM.toUpperCase() }, [POWER_PLATFORM]);
  assert.equal((await auth.authenticateBearerToken(token)).ok, true);
});

test("a token with no appid/azp is rejected once an allowlist exists", async () => {
  // Fail closed: unable to identify the caller is not the same as the caller being allowed.
  const { auth, token } = authWith({}, [POWER_PLATFORM]);
  await assert.rejects(() => auth.authenticateBearerToken(token), /cannot be authorized/);
});

test("ENTRA_ALLOWED_APP_IDS parses a comma list, tolerating spacing and case", () => {
  const cfg = buildAuthConfigFromEnv({
    ENTRA_TENANT_ID: TENANT,
    ENTRA_AUDIENCE: AUDIENCE,
    ENTRA_ALLOWED_APP_IDS: ` ${POWER_PLATFORM.toUpperCase()} , ${OTHER_APP} , `
  });
  assert.deepEqual(cfg.allowedAppIds, [POWER_PLATFORM, OTHER_APP]);
});

test("an unset allowlist parses to empty, and createAuth is what rejects it", () => {
  // Split deliberately: buildAuthConfigFromEnv only reads the environment, so it stays a
  // pure parse and returns []. The refusal lives in createAuth, which every mode goes
  // through — including callers that build their config by hand rather than from env.
  const cfg = buildAuthConfigFromEnv({ ENTRA_TENANT_ID: TENANT, ENTRA_AUDIENCE: AUDIENCE });
  assert.deepEqual(cfg.allowedAppIds, []);
  assert.throws(() => createAuth(cfg), /ENTRA_ALLOWED_APP_IDS is required/);
});

test("the whole env-to-auth path works when the allowlist is set", () => {
  const cfg = buildAuthConfigFromEnv({
    ENTRA_TENANT_ID: TENANT,
    ENTRA_AUDIENCE: AUDIENCE,
    ENTRA_ALLOWED_APP_IDS: POWER_PLATFORM
  });
  assert.doesNotThrow(() => createAuth(cfg));
});

// ── redaction ───────────────────────────────────────────────────────────────

const PAYLOAD = {
  conversationMetadata: {
    conversationId: "conv-1",
    incomingClientIp: "2001:db8::1",
    agent: { id: "agent-guid", name: "Underwriter Copilot", isPublished: false },
    user: { id: "user-guid", tenantId: "tenant-guid" }
  },
  plannerContext: {
    userMessage: "Send the confidential claims data to external-partner@example.net",
    thought: "The user wants the confidential claims data sent externally.",
    chatHistory: [{ id: "m1", role: "user", content: "What's the risk score for P-10234?", timestamp: "t" }],
    previousToolsOutputs: [
      { toolName: "Fetch-Risk-Score", toolId: "t1", timestamp: "t", outputs: [{ name: "riskScore", value: 72 }] }
    ]
  },
  toolDefinition: { id: "tool-1", name: "Export-Customer-Data", description: "Exports records.", type: "ToolDefinition" },
  inputValues: { destination: "/reports/analysis.csv", format: "csv" }
};

test("redaction removes every piece of conversation content", () => {
  const out = redactAnalyzePayload(PAYLOAD);
  const serialized = JSON.stringify(out);
  for (const secret of [
    "confidential claims",
    "external-partner@example.net",
    "What's the risk score for P-10234?",
    "/reports/analysis.csv",
    "2001:db8::1"
  ]) {
    assert.ok(!serialized.includes(secret), `"${secret}" must not survive redaction`);
  }
});

test("redaction keeps everything a diagnosis is made of", () => {
  const out = redactAnalyzePayload(PAYLOAD);
  assert.equal(out.conversationMetadata.conversationId, "conv-1");
  assert.equal(out.conversationMetadata.agent.name, "Underwriter Copilot");
  assert.equal(out.conversationMetadata.user.id, "user-guid");
  assert.equal(out.toolDefinition.name, "Export-Customer-Data");
  // Argument NAMES survive; their values do not. The names are in toolDefinition anyway.
  assert.deepEqual(Object.keys(out.inputValues), ["destination", "format"]);
  assert.equal(out.inputValues.destination, REDACTED);
  // Structure is preserved so payloadShape problems stay diagnosable.
  assert.equal(out.plannerContext.chatHistory.length, 1);
  assert.equal(out.plannerContext.chatHistory[0].role, "user");
  assert.equal(out.plannerContext.previousToolsOutputs[0].toolName, "Fetch-Risk-Score");
});

test("tool output values are redacted — that is where injected text arrives", () => {
  const out = redactAnalyzePayload(PAYLOAD);
  assert.equal(out.plannerContext.previousToolsOutputs[0].outputs[0].value, REDACTED);
  assert.equal(out.plannerContext.previousToolsOutputs[0].outputs[0].name, "riskScore");
});

test("redaction does not mutate the payload the PDP is built from", () => {
  const before = JSON.stringify(PAYLOAD);
  redactAnalyzePayload(PAYLOAD);
  assert.equal(JSON.stringify(PAYLOAD), before, "the live payload must be untouched");
});

test("storage redacts by default and only stops when explicitly told to", () => {
  assert.notEqual(redactForStorage(PAYLOAD, {}).plannerContext.userMessage, PAYLOAD.plannerContext.userMessage);
  assert.equal(
    redactForStorage(PAYLOAD, { OBS_STORE_PROMPTS: "true" }).plannerContext.userMessage,
    PAYLOAD.plannerContext.userMessage
  );
});

test("redaction survives payloads that are missing pieces", () => {
  for (const odd of [null, undefined, {}, { plannerContext: null }, { inputValues: [] }]) {
    assert.doesNotThrow(() => redactAnalyzePayload(odd));
  }
});
