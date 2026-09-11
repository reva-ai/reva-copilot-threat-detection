import { buildAuthConfigFromEnv, createAuth } from "../core/auth.mjs";
import {
  createThreatResponse,
  evaluateToolExecution,
  sanitizeMicrosoftAnalyzeResponse,
  isCopilotTopicInvocation,
  REASON_CODE_AUTHZ_UNAVAILABLE
} from "../core/policy.mjs";
import {
  buildRevaPdpConfigFromEnv,
  isRevaPdpConfigured,
  evaluateViaRevaPdp,
  summarizePdpDiagnostics
} from "../core/pdp.mjs";
import {
  getHeader,
  parseAuthorization,
  withCorrelation,
  jsonResponse,
  unauthorized,
  methodNotAllowed,
  badRequest,
  parseJsonBody
} from "../core/http.mjs";
import { getPolicyConfig, appendObservabilityEvent } from "../storage/index.mjs";
import { redactForStorage } from "../core/redact.mjs";

const AUTH = createAuth(buildAuthConfigFromEnv(process.env));
const REVA_PDP_CONFIG = buildRevaPdpConfigFromEnv(process.env);
// Copilot topics (".topic." ids) are pseudo-tools, not real executions — skip them by
// default. Set EVALUATE_COPILOT_TOPICS=true to send them to the PDP like real tools.
const EVALUATE_COPILOT_TOPICS =
  process.env.EVALUATE_COPILOT_TOPICS === "true" || process.env.EVALUATE_COPILOT_TOPICS === "1";

/**
 * Microsoft's documented budget for this webhook, and it is not a soft one: "If your system
 * doesn't respond in time, the agent behaves as if your response is 'allow', invoking the
 * tool." Newer Power Platform environments can invert that with an error behaviour of
 * "Block the query", which turns being slow into a refusal instead. Either way, exceeding
 * the budget replaces the decision this service made with one it did not.
 *
 * Not a timeout — nothing here aborts at 1000 ms, because a PDP that answers at 1200 ms is
 * still worth waiting for on the calls where Copilot has not yet given up. It is a marker,
 * so the event log can answer "how often are we too late to matter?"
 *
 * WHAT THE MARKER CANNOT SEE. Everything measured here is server-side. The client-to-gateway
 * network is not, and on a distant deployment it is the larger half: measured from an Indian
 * Power Platform region against a us-east-1 gateway, a fresh connection spent 760-875 ms on
 * DNS, TCP and TLS before the request body was even sent. A `serverBudgetExceeded: false`
 * event is therefore not evidence that Copilot got its answer in time, and one was observed
 * being blocked for slowness while this said the call was comfortably inside budget. Deploy
 * near the Power Platform region; see INSTALL.md.
 */
const COPILOT_BUDGET_MS = 1000;

/**
 * Why we could not get a decision, in words aimed at whoever is holding the pager. Each one
 * has to point at a different place to look, which is the entire reason these are not one
 * message: "invalid-payload" means the PDP answered and rejected what we sent — a bug on
 * this side — while "transport" means it never answered at all.
 *
 * "upstream-blocked" is the third case and it is neither: the PDP was never asked, because a
 * CDN or WAF in front of it refused the request. It reads differently on purpose. The fix is
 * an exemption in someone else's infrastructure config, not a change here, and the message
 * has to say so or the time goes into the request builder instead.
 */
const FAILURE_DETAIL = {
  "no-principal": "this request does not identify the end user",
  timeout: "the authorization service did not respond in time",
  auth: "the authorization service rejected our credentials",
  "invalid-payload": "the authorization service rejected this request as malformed",
  "upstream-blocked":
    "a CDN or WAF in front of the authorization service blocked this request before it arrived",
  transport: "the authorization service could not be reached"
};

function validateAnalyzePayload(payload) {
  if (!payload || typeof payload !== "object") {
    return "Request body must be a JSON object.";
  }
  if (!payload.toolDefinition || typeof payload.toolDefinition !== "object") {
    return "Request body must include toolDefinition.";
  }
  const hasInputParameters = Array.isArray(payload.inputParameters);
  const hasInputValues =
    payload.inputValues && typeof payload.inputValues === "object" && !Array.isArray(payload.inputValues);
  if (!hasInputParameters && !hasInputValues) {
    return "Request body must include inputParameters as an array, or inputValues as an object.";
  }
  return null;
}

function normalizeAnalyzePayload(payload) {
  const plannerContext =
    payload.plannerContext && typeof payload.plannerContext === "object" ? { ...payload.plannerContext } : {};

  if (!Array.isArray(plannerContext.previousToolOutputs) && Array.isArray(plannerContext.previousToolsOutputs)) {
    plannerContext.previousToolOutputs = plannerContext.previousToolsOutputs;
  }

  let inputParameters = [];
  if (Array.isArray(payload.inputParameters)) {
    inputParameters = payload.inputParameters;
  } else if (payload.inputValues && typeof payload.inputValues === "object" && !Array.isArray(payload.inputValues)) {
    inputParameters = Object.entries(payload.inputValues).map(([name, value]) => ({ name, value }));
  }

  return {
    ...payload,
    plannerContext,
    inputParameters
  };
}

/**
 * How long ago the host received this request.
 *
 * `startedMs` is taken inside this route, which misses two things that are firmly inside the
 * deadline Copilot is measuring against: the cold-start module init (imports, createAuth,
 * config parsing — all before the route is entered) and any queueing in front of it. On a
 * cold container that is not a rounding error.
 *
 * The adapter supplies `receivedAtMs`, which recovers both. It stays host-agnostic on
 * purpose: the Lambda adapter reads API Gateway's stamp, the node adapter takes it when the
 * request arrives, and a route called directly — as tests do — simply has none. Absent means
 * null rather than a guess.
 *
 * Two clocks can be involved, so a small negative is possible under skew. That is reported as
 * null too: an impossible number in a latency field is worse than an absent one.
 */
function gatewayElapsedMs(req) {
  const receivedAt = req?.receivedAtMs;
  if (!Number.isFinite(receivedAt)) return null;
  const elapsed = Date.now() - receivedAt;
  return elapsed >= 0 ? elapsed : null;
}
/**
 * True until the first invocation on this container answers.
 *
 * A cold start is the single biggest thing that pushes a response past Microsoft's budget:
 * the JWKS fetch, the DynamoDB connection and the TLS handshake to the PDP all happen once,
 * and the request that pays for them is the one Copilot has already stopped waiting for. A
 * 4-second response looks alarming and a 300 ms one looks fine, and until this flag existed
 * the event could not tell you which kind you were reading.
 */
let coldStart = true;

export const handleAnalyzeToolExecution = async (req) => {
  // Microsoft allows this webhook about 1000 ms and treats anything slower as "allow", so
  // our own end-to-end time is the number that matters — not the PDP call alone. Measured
  // here rather than inferred, because the budget is the one thing we cannot negotiate.
  const startedMs = Date.now();
  const wasColdStart = coldStart;
  coldStart = false;
  // Phase timings, so a slow response says WHERE it was slow. Only the PDP leg was ever
  // measured, which left "3.3 seconds happened somewhere else" as the whole diagnosis.
  let authMs = null;
  let jwksFetched = null;
  const headers = req.headers || {};
  if ((req.method || "GET") !== "POST") {
    return withCorrelation(headers, methodNotAllowed());
  }

  const token = parseAuthorization(headers);
  let authResult;
  try {
    const authStartedMs = Date.now();
    authResult = await AUTH.authenticateBearerToken(token);
    authMs = Date.now() - authStartedMs;
    jwksFetched = authResult.jwksFetched ?? null;
  } catch (err) {
    await appendObservabilityEvent({
      path: "/analyze-tool-execution",
      method: "POST",
      statusCode: 401,
      authType: "invalid",
      correlationId: getHeader(headers, "x-ms-correlation-id") || null,
      requestPayload: null,
      response: {
        errorCode: 4010,
        message: "Unauthorized.",
        diagnostics: err.message
      }
    });
    return withCorrelation(headers, unauthorized(err.message));
  }

  if (!authResult.ok) {
    await appendObservabilityEvent({
      path: "/analyze-tool-execution",
      method: "POST",
      statusCode: 401,
      authType: "invalid",
      correlationId: getHeader(headers, "x-ms-correlation-id") || null,
      requestPayload: null,
      response: {
        errorCode: 4010,
        message: "Unauthorized.",
        diagnostics: authResult.reason
      }
    });
    return withCorrelation(headers, unauthorized(authResult.reason));
  }

  let payload;
  try {
    payload = parseJsonBody(req.body);
  } catch (err) {
    await appendObservabilityEvent({
      path: "/analyze-tool-execution",
      method: "POST",
      statusCode: 400,
      authType: authResult.authType || "unknown",
      correlationId: getHeader(headers, "x-ms-correlation-id") || null,
      requestPayload: null,
      response: {
        errorCode: 4000,
        message: "Invalid request body.",
        diagnostics: err.message
      }
    });
    return withCorrelation(headers, badRequest("Invalid request body.", err.message));
  }

  const validationError = validateAnalyzePayload(payload);
  if (validationError) {
    await appendObservabilityEvent({
      path: "/analyze-tool-execution",
      method: "POST",
      statusCode: 400,
      authType: authResult.authType || "unknown",
      correlationId: getHeader(headers, "x-ms-correlation-id") || null,
      requestPayload: redactForStorage(payload),
      response: {
        errorCode: 4000,
        message: validationError
      }
    });
    return withCorrelation(headers, badRequest(validationError));
  }

  const normalizedPayload = normalizeAnalyzePayload(payload);
  const correlationId = getHeader(headers, "x-ms-correlation-id") || null;

  // Copilot Studio topics are surfaced to the planner as pseudo-tools and hit this webhook
  // (even when disabled in the agent), producing duplicate/blank-named decision-log noise.
  // They are not real tool executions, so allow them without consulting the PDP or storage.
  if (!EVALUATE_COPILOT_TOPICS && isCopilotTopicInvocation(normalizedPayload.toolDefinition)) {
    return withCorrelation(headers, jsonResponse(200, { blockAction: false }));
  }

  let policyResult;
  let pdpDiagnostics = null;
  /** Set only in monitor mode, and only when the PDP actually said deny. */
  let monitorWouldDeny = null;

  if (isRevaPdpConfigured(REVA_PDP_CONFIG)) {
    // No getPolicyConfig() here, and no computeBlockedFlags(). Both used to run on this
    // path and neither reached a decision: the blocked-term flags were removed from the PDP
    // request long ago — no policy referenced them and they were never in the schema — so
    // all they did was cost a DynamoDB read per request and land a field in the event that
    // nothing reads. On a control with a 1000 ms budget that is not free.
    //
    // The terms themselves are untouched and still decide the fallback below, which is the
    // only place they ever had authority.
    const pdpOutcome = await evaluateViaRevaPdp(
      normalizedPayload,
      REVA_PDP_CONFIG,
      authResult,
      correlationId
    );
    if (!pdpOutcome.ok) {
      // Fail CLOSED by default. Returning a non-200 here would hand the decision to Power
      // Platform's admin-center error behavior, whose default is to allow — so a PDP outage
      // would silently permit every tool call. Answer Microsoft with a real decision, and
      // make the reason name a SERVICE failure so nobody goes looking through Cedar.
      // Carried to the single event written at the end of this handler. A failure used to
      // append its own event here AND fall through to that one, so one Copilot request
      // produced two rows: this one with no `blockAction` (the dashboard renders it "N/A")
      // and the real verdict separately, under the same correlationId. It read as the
      // service answering twice, differently. One request, one event.
      pdpDiagnostics = pdpOutcome.diagnostics;
      const kind = pdpOutcome.diagnostics?.errorKind || "transport";
      const detail = FAILURE_DETAIL[kind] || FAILURE_DETAIL.transport;

      policyResult = REVA_PDP_CONFIG.failOpen
        ? {
            blockAction: false,
            reason: `Allowed without authorization: ${detail} (REVA_FAIL_OPEN is set).`,
            details: { source: "reva-pdp-unavailable", errorKind: kind }
          }
        : {
            blockAction: true,
            reasonCode: REASON_CODE_AUTHZ_UNAVAILABLE,
            reason: `Not authorized: ${detail}. This is a service problem, not a policy decision.`,
            details: { source: "reva-pdp-unavailable", errorKind: kind }
          };
    } else {
      policyResult = pdpOutcome.policyResult;
      pdpDiagnostics = pdpOutcome.diagnostics;

      // MONITOR mode. The decision was real and is recorded in full; the call proceeds
      // anyway. Only a genuine policy DENY is overridden here — a PDP fault took the branch
      // above and is governed by REVA_FAIL_OPEN, so watching policy never also disarms the
      // outage path.
      if (REVA_PDP_CONFIG.monitorMode && policyResult.blockAction) {
        monitorWouldDeny = {
          // The PDP's own words when we have them. policyResult.reason is the generic
          // "Blocked by Reva authorization policy" unless REVA_PDP_SURFACE_RESPONSE is set,
          // and a monitor run that cannot say WHY is not worth doing.
          reason: pdpDiagnostics?.pdpReason || policyResult.reason,
          reasonCode: policyResult.reasonCode ?? null
        };
        policyResult = {
          blockAction: false,
          reason: `Allowed in monitor mode (REVA_MODE). Reva would have denied this: ${policyResult.reason}`,
          details: { ...(policyResult.details || {}), monitorWouldDeny: true }
        };
      }
    }
  } else {
    // The only path where the configured terms decide anything, so the read happens here.
    const policyRow = await getPolicyConfig();
    policyResult = evaluateToolExecution(normalizedPayload, {
      blockedTerms: policyRow.blockedTerms,
      blockedToolNames: policyRow.blockedToolNames
    });
  }

  const result = createThreatResponse(policyResult);
  const copilotBody = sanitizeMicrosoftAnalyzeResponse(result);

  await appendObservabilityEvent({
    path: "/analyze-tool-execution",
    method: "POST",
    statusCode: 200,
    authType: authResult.authType || "unknown",
    correlationId,
    requestPayload: redactForStorage(payload),
    response: copilotBody,
    // Shape only — counts, entity resolution and any size trimming. No prompt text, so it
    // is safe to leave on, and a conversation/hops divergence is visible here first.
    pdp: pdpDiagnostics ? summarizePdpDiagnostics(pdpDiagnostics) : undefined,
    // Which application Entra issued the caller's token to. Recorded even when
    // ENTRA_ALLOWED_APP_IDS is unset, because it is the only evidence-based way to populate
    // that allowlist — read it here, then pin it.
    callerAppId: authResult.callerAppId || undefined,
    // Our own end-to-end time against Microsoft's ~1000 ms budget, past which Copilot stops
    // waiting and invokes the tool anyway. A run of `budgetExceeded: true` means the
    // enforcement point is being bypassed by timeout, whatever the decisions say.
    latency: (() => {
      const serverTotalMs = Date.now() - startedMs;
      const pdpMs = pdpDiagnostics?.latencyMs ?? null;
      // Whatever the two named legs do not account for: body parse, redaction, and on the
      // fallback path the config read. Derived rather than measured, so nothing hides
      // between them — but see the note above about what it cannot see.
      const otherMs = serverTotalMs - (authMs ?? 0) - (pdpMs ?? 0);
      const gatewayMs = gatewayElapsedMs(req);
      // Judged on the gateway clock when we have one, because it is the closer of the two
      // to what Copilot is actually timing.
      const budgetBasisMs = gatewayMs ?? serverTotalMs;
      return {
        gatewayMs,
        serverTotalMs,
        authMs,
        pdpMs,
        otherMs,
        budgetMs: COPILOT_BUDGET_MS,
        serverBudgetExceeded: budgetBasisMs > COPILOT_BUDGET_MS,
        // The two that turn "probably a cold start" into a fact.
        coldStart: wasColdStart,
        jwksFetched
      };
    })(),
    // The whole product of a monitor-mode run. `response` above says the call was allowed,
    // which is true and is also the opposite of what happened in policy terms, so the
    // would-be denial is recorded separately rather than inferred from a passing event.
    monitorWouldDeny: monitorWouldDeny || undefined
  });
  return withCorrelation(headers, jsonResponse(200, copilotBody));
};
