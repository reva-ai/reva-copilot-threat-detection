import test from "node:test";
import assert from "node:assert/strict";
import { clearObservabilityEvents, listObservabilityEvents } from "../src/storage/index.mjs";

/**
 * One Copilot request must produce exactly one observability event.
 *
 * It used to produce two whenever the PDP call failed: the failure branch appended its own
 * event and then fell through to the append at the end of the route. Both carried the same
 * x-ms-correlation-id and the same request payload, but only one of them had `blockAction`,
 * so the dashboard rendered the pair as an "N/A" row beside a "Block" row and the service
 * looked like it had answered the same question twice, differently.
 *
 * The count is the assertion. A duplicate is not cosmetic: these rows are the evidence an
 * operator reaches for when reconstructing what the service decided and why.
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

const request = () => ({
  method: "POST",
  path: "/analyze-tool-execution",
  headers: {
    authorization: "Bearer dev-token",
    "content-type": "application/json",
    "x-ms-correlation-id": "cid-1"
  },
  body: JSON.stringify(PAYLOAD)
});

function stubFetch(impl) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return () => {
    globalThis.fetch = original;
  };
}

const ALLOW = async () => new Response(JSON.stringify({ decision: true }), { status: 200 });

/** The CloudFront error page an AWS WAF returns in front of the PDP. */
const WAF_BLOCK = async () =>
  new Response("<HTML><HEAD><TITLE>403 ERROR</TITLE></HEAD><BODY>Request blocked.</BODY></HTML>", {
    status: 403,
    headers: { "content-type": "text/html", server: "CloudFront" }
  });

const CASES = [
  { label: "an allow", fetchImpl: ALLOW, blockAction: false },
  { label: "an upstream WAF block", fetchImpl: WAF_BLOCK, blockAction: true },
  {
    label: "a transport failure",
    fetchImpl: async () => {
      throw new Error("ECONNREFUSED");
    },
    blockAction: true
  }
];

for (const { label, fetchImpl, blockAction } of CASES) {
  test(`${label} writes exactly one event`, async () => {
    await clearObservabilityEvents();
    const { handleAnalyzeToolExecution } = await loadRoute(BASE_ENV);
    const restore = stubFetch(fetchImpl);
    try {
      await handleAnalyzeToolExecution(request());
      const events = await listObservabilityEvents(50);
      assert.equal(events.length, 1, `expected 1 event, got ${events.length}`);

      // The one event has to be the useful one: it carries the verdict the dashboard badges.
      const [only] = events;
      assert.equal(only.correlationId, "cid-1");
      assert.equal(
        typeof only.response?.blockAction,
        "boolean",
        "the surviving event must carry a decision, or the dashboard renders it N/A"
      );
      assert.equal(only.response.blockAction, blockAction);
    } finally {
      restore();
    }
  });
}

test("a PDP failure keeps its diagnostics on the single event it now writes", async () => {
  // Removing the second append must not lose what it carried. Everything an operator needs
  // to place the blame — status, kind, and the body that proves who answered — moves onto
  // the surviving event under `pdp`.
  await clearObservabilityEvents();
  const { handleAnalyzeToolExecution } = await loadRoute(BASE_ENV);
  const restore = stubFetch(WAF_BLOCK);
  try {
    await handleAnalyzeToolExecution(request());
    const [only] = await listObservabilityEvents(50);
    assert.equal(only.pdp.httpStatus, 403);
    assert.equal(only.pdp.errorKind, "upstream-blocked");
    assert.match(only.pdp.responsePreview, /403 ERROR/);
    assert.match(only.response.reason, /CDN or WAF/);
  } finally {
    restore();
  }
});
