import { buildAuthConfigFromEnv, createAuth } from "../core/auth.mjs";
import {
  createThreatResponse,
  evaluateToolExecution,
  computeBlockedFlags,
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
 * tool." Exceeding it does not slow enforcement down, it removes it.
 *
 * Not a timeout — nothing here aborts at 1000 ms, because a PDP that answers at 1200 ms is
 * still worth waiting for on the calls where Copilot has not yet given up. It is a marker,
 * so the event log can answer "how often are we too late to matter?"
 */
const COPILOT_BUDGET_MS = 1000;

/**
 * Why we could not get a decision, in words aimed at whoever is holding the pager. Each one
 * has to point at a different place to look, which is the entire reason these are not one
 * message: "invalid-payload" means the PDP answered and rejected what we sent — a bug on
 * this side — while "transport" means it never answered at all.
 */
const FAILURE_DETAIL = {
  "no-principal": "this request does not identify the end user",
  timeout: "the authorization service did not respond in time",
  auth: "the authorization service rejected our credentials",
  "invalid-payload": "the authorization service rejected this request as malformed",
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

export const handleAnalyzeToolExecution = async (req) => {
  // Microsoft allows this webhook about 1000 ms and treats anything slower as "allow", so
  // our own end-to-end time is the number that matters — not the PDP call alone. Measured
  // here rather than inferred, because the budget is the one thing we cannot negotiate.
  const startedMs = Date.now();
  const headers = req.headers || {};
  if ((req.method || "GET") !== "POST") {
    return withCorrelation(headers, methodNotAllowed());
  }

  const token = parseAuthorization(headers);
  let authResult;
  try {
    authResult = await AUTH.authenticateBearerToken(token);
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

  const policyRow = await getPolicyConfig();

  let policyResult;
  let pdpDiagnostics = null;
  /** Set only in monitor mode, and only when the PDP actually said deny. */
  let monitorWouldDeny = null;

  if (isRevaPdpConfigured(REVA_PDP_CONFIG)) {
    const computedFlags = computeBlockedFlags(normalizedPayload, {
      blockedTerms: policyRow.blockedTerms,
      blockedToolNames: policyRow.blockedToolNames
    });
    const pdpOutcome = await evaluateViaRevaPdp(
      normalizedPayload,
      computedFlags,
      REVA_PDP_CONFIG,
      authResult,
      correlationId
    );
    if (!pdpOutcome.ok) {
      // Fail CLOSED by default. Returning a non-200 here would hand the decision to Power
      // Platform's admin-center error behavior, whose default is to allow — so a PDP outage
      // would silently permit every tool call. Answer Microsoft with a real decision, and
      // make the reason name a SERVICE failure so nobody goes looking through Cedar.
      const summary = summarizePdpDiagnostics(pdpOutcome.diagnostics);
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

      await appendObservabilityEvent({
        path: "/analyze-tool-execution",
        method: "POST",
        statusCode: 200,
        authType: authResult.authType || "unknown",
        correlationId,
        requestPayload: redactForStorage(payload),
        response: {
          errorCode: 5020,
          message: "Reva PDP evaluation failed.",
          failOpen: Boolean(REVA_PDP_CONFIG.failOpen),
          diagnostics: JSON.stringify(summary)
        }
      });
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
      const totalMs = Date.now() - startedMs;
      return { totalMs, budgetMs: COPILOT_BUDGET_MS, budgetExceeded: totalMs > COPILOT_BUDGET_MS };
    })(),
    // The whole product of a monitor-mode run. `response` above says the call was allowed,
    // which is true and is also the opposite of what happened in policy terms, so the
    // would-be denial is recorded separately rather than inferred from a passing event.
    monitorWouldDeny: monitorWouldDeny || undefined
  });
  return withCorrelation(headers, jsonResponse(200, copilotBody));
};
