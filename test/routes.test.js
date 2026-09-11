import test from "node:test";
import assert from "node:assert/strict";

/**
 * Route- and adapter-level behaviour: the security controls, and the contract Copilot
 * actually calls.
 *
 * The analyze route reads its configuration at module scope, so each environment needs its
 * own module instance. A cache-busting query on the import URL gives one — which is the
 * whole benefit of routes being plain functions rather than Lambda handlers: no temp
 * directories, no staging, no filesystem.
 */
let seq = 0;
async function loadRoute(file, env = {}) {
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await import(new URL(`../src/routes/${file}?v=${++seq}`, import.meta.url).href);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const BASE_ENV = {
  ALLOW_INSECURE_LOCAL_AUTH: "true",
  AUTH_TOKEN: "dev-token",
  REVA_PDP_URL: "https://pdp.example/pdp/v2/ai/evaluation",
  REVA_POLICY_STORE_ID: "store-1",
  REVA_PDP_TOKEN: "tok",
  REVA_PDP_TIMEOUT_MS: "200"
};

const PAYLOAD = {
  plannerContext: { userMessage: "Send an email", thought: "notify", chatHistory: [], previousToolOutputs: [] },
  toolDefinition: { id: "tool-1", type: "ToolDefinition", name: "Send-Email", description: "Sends mail." },
  inputValues: { to: "customer@example.com" },
  conversationMetadata: {
    agent: { id: "agent-1", tenantId: "t", environmentId: "e", isPublished: true },
    user: { id: "user-1", tenantId: "t" },
    conversationId: "conv-1"
  }
};

const request = (over = {}) => ({
  method: "POST",
  path: "/analyze-tool-execution",
  headers: { authorization: "Bearer dev-token", "content-type": "application/json" },
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

const DENY = async () =>
  new Response(
    JSON.stringify({ decision: false, error_type: "POLICY_DENIED", context: { reason: "forbidden by policy P-9" } }),
    { status: 403 }
  );

// ── enforcement mode ────────────────────────────────────────────────────────

test("enforce mode blocks on a policy deny", async () => {
  const { handleAnalyzeToolExecution } = await loadRoute("analyze-tool-execution.mjs", BASE_ENV);
  const restore = stubFetch(DENY);
  try {
    const body = JSON.parse((await handleAnalyzeToolExecution(request())).body);
    assert.equal(body.blockAction, true);
    assert.equal(body.reasonCode, 101);
  } finally {
    restore();
  }
});

test("monitor mode allows the same deny", async () => {
  const { handleAnalyzeToolExecution } = await loadRoute("analyze-tool-execution.mjs", {
    ...BASE_ENV,
    REVA_MODE: "monitor"
  });
  const restore = stubFetch(DENY);
  try {
    const body = JSON.parse((await handleAnalyzeToolExecution(request())).body);
    assert.equal(body.blockAction, false);
    assert.match(body.reason, /monitor mode/i);
  } finally {
    restore();
  }
});

test("monitor mode does NOT relax a PDP fault — that is REVA_FAIL_OPEN's job", async () => {
  const { handleAnalyzeToolExecution } = await loadRoute("analyze-tool-execution.mjs", {
    ...BASE_ENV,
    REVA_MODE: "monitor"
  });
  const restore = stubFetch(async () => {
    throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
  });
  try {
    const body = JSON.parse((await handleAnalyzeToolExecution(request())).body);
    assert.equal(body.blockAction, true, "a fault still fails closed in monitor mode");
    assert.equal(body.reasonCode, 103);
  } finally {
    restore();
  }
});

// ── the Microsoft contract ──────────────────────────────────────────────────

test("validate answers Microsoft's documented shape to an EMPTY body", async () => {
  const { handleValidate } = await loadRoute("validate.mjs", BASE_ENV);
  const res = await handleValidate({
    method: "POST",
    path: "/validate",
    headers: { authorization: "Bearer dev-token" },
    body: ""
  });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { isSuccessful: true, status: "OK" });
});

test("the analyze response carries only keys Microsoft defines", async () => {
  // AnalyzeToolExecutionResponse: blockAction (required), reasonCode, reason, diagnostics.
  // Anything else risks being rejected by a platform we do not control.
  const { handleAnalyzeToolExecution } = await loadRoute("analyze-tool-execution.mjs", BASE_ENV);
  const restore = stubFetch(async () => new Response(JSON.stringify({ decision: true }), { status: 200 }));
  try {
    const body = JSON.parse((await handleAnalyzeToolExecution(request())).body);
    for (const k of Object.keys(body)) {
      assert.ok(["blockAction", "reasonCode", "reason", "diagnostics"].includes(k), `unexpected key "${k}"`);
    }
    assert.equal(typeof body.blockAction, "boolean");
    if ("diagnostics" in body) assert.equal(typeof body.diagnostics, "string", "must be preserialized");
  } finally {
    restore();
  }
});

test("an unauthenticated call is refused", async () => {
  const { handleAnalyzeToolExecution } = await loadRoute("analyze-tool-execution.mjs", BASE_ENV);
  const res = await handleAnalyzeToolExecution(request({ headers: { "content-type": "application/json" } }));
  assert.equal(res.statusCode, 401);
});

// ── observability is closed by default ──────────────────────────────────────

const OBS = [
  ["handleObservabilityEvents", "GET"],
  ["handleObservabilityEventsClear", "DELETE"]
];

/**
 * These read CONFIG_API_TOKEN at CALL time (unlike the analyze route, which reads its
 * config at module scope), so the environment has to be set around the invocation.
 */
async function callObs(fn, { token, method, headers = {} }) {
  const mod = await import(new URL("../src/routes/observability.mjs", import.meta.url).href);
  const saved = process.env.CONFIG_API_TOKEN;
  if (token === undefined) delete process.env.CONFIG_API_TOKEN;
  else process.env.CONFIG_API_TOKEN = token;
  try {
    return await mod[fn]({ method, headers, body: "" });
  } finally {
    if (saved === undefined) delete process.env.CONFIG_API_TOKEN;
    else process.env.CONFIG_API_TOKEN = saved;
  }
}

for (const [fn, method] of OBS) {
  test(`${fn} refuses without a token`, async () => {
    const res = await callObs(fn, { token: "s3cret", method });
    assert.equal(res.statusCode, 401, "must not serve stored events unauthenticated");
  });

  test(`${fn} refuses a wrong token`, async () => {
    const res = await callObs(fn, { token: "s3cret", method, headers: { "x-config-token": "guess" } });
    assert.equal(res.statusCode, 401);
  });

  test(`${fn} serves the correct token`, async () => {
    const res = await callObs(fn, { token: "s3cret", method, headers: { "x-config-token": "s3cret" } });
    assert.equal(res.statusCode, 200);
  });

  test(`${fn} is DISABLED, not open, when CONFIG_API_TOKEN is unset`, async () => {
    // Forgetting to configure a token must yield a dark dashboard, never an open one.
    const res = await callObs(fn, { token: undefined, method, headers: { "x-config-token": "anything" } });
    assert.notEqual(res.statusCode, 200, "an unconfigured route must never serve data");
    assert.equal(res.statusCode, 400);
  });
}

// ── adapters ────────────────────────────────────────────────────────────────

test("the Lambda adapter normalises API Gateway events, including base64 bodies", async () => {
  // The adapter pulls in the routes, whose auth config refuses to load unconfigured — that
  // fail-closed behaviour is deliberate, so the test supplies an environment.
  const saved = { ...process.env };
  Object.assign(process.env, BASE_ENV);
  let toRequest;
  try {
    ({ toRequest } = await import("../src/adapters/lambda/index.mjs"));
  } finally {
    for (const k of Object.keys(BASE_ENV)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
  const http = toRequest({
    requestContext: { http: { method: "POST" } },
    rawPath: "/analyze-tool-execution",
    headers: { a: "b" },
    body: Buffer.from('{"x":1}').toString("base64"),
    isBase64Encoded: true
  });
  assert.deepEqual(http, {
    method: "POST",
    path: "/analyze-tool-execution",
    headers: { a: "b" },
    body: '{"x":1}',
    receivedAtMs: null
  });

  // REST API events use httpMethod/path instead; both must reduce to the same shape.
  const rest = toRequest({ httpMethod: "GET", path: "/validate", headers: {}, body: null });
  assert.equal(rest.method, "GET");
  assert.equal(rest.path, "/validate");
  assert.equal(rest.body, "");

  // The gateway's receive stamp is carried through so a route can measure the part of the
  // budget spent before it was entered. HTTP APIs name it timeEpoch, REST APIs
  // requestTimeEpoch, and an event with neither must yield null rather than 0 or NaN.
  assert.equal(toRequest({ requestContext: { timeEpoch: 1750000000000 } }).receivedAtMs, 1750000000000);
  assert.equal(toRequest({ requestContext: { requestTimeEpoch: 1750000000001 } }).receivedAtMs, 1750000000001);
  assert.equal(toRequest({ requestContext: {} }).receivedAtMs, null);
  assert.equal(toRequest({}).receivedAtMs, null);
});

// ── the allowlist is a startup requirement, not a runtime warning ────────────
//
// Proven at the route module, not just at createAuth, because that is the layer a
// deployment actually loads: both routes build their auth at module scope, so an
// unconfigured allowlist kills the Lambda cold start or the node process instead of
// quietly serving traffic with only a tenant and audience check in front of it.

for (const file of ["analyze-tool-execution.mjs", "validate.mjs"]) {
  test(`${file} refuses to load in entra mode without an allowlist`, async () => {
    await assert.rejects(
      () =>
        loadRoute(file, {
          ALLOW_INSECURE_LOCAL_AUTH: undefined,
          AUTH_TOKEN: undefined,
          ENTRA_TENANT_ID: "11111111-1111-1111-1111-111111111111",
          ENTRA_AUDIENCE: "https://td.example.com",
          ENTRA_ALLOWED_APP_IDS: undefined
        }),
      /ENTRA_ALLOWED_APP_IDS is required/
    );
  });

  test(`${file} loads once the allowlist is set`, async () => {
    const mod = await loadRoute(file, {
      ALLOW_INSECURE_LOCAL_AUTH: undefined,
      AUTH_TOKEN: undefined,
      ENTRA_TENANT_ID: "11111111-1111-1111-1111-111111111111",
      ENTRA_AUDIENCE: "https://td.example.com",
      ENTRA_ALLOWED_APP_IDS: "22222222-2222-2222-2222-222222222222"
    });
    assert.equal(typeof Object.values(mod)[0], "function");
  });
}
