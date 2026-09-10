const DEFAULT_BLOCK_MESSAGE =
  "This tool execution was blocked by the external threat detection policy.";

/** Partner-defined codes for Microsoft AnalyzeToolExecutionResponse (small integers per Copilot guidance). */
export const REASON_CODE_BLOCKED_LOCAL_POLICY = 102;
export const REASON_CODE_BLOCKED_REVA_PDP = 101;
/**
 * The authorization service could not be reached or could not answer. Deliberately distinct
 * from a policy block: "blocked by policy" sends the reader into Cedar, "could not reach the
 * authorization service" sends them to their configuration. Wrong message, wrong day of
 * debugging.
 */
export const REASON_CODE_AUTHZ_UNAVAILABLE = 103;

function stringifyDiagnostics(value) {
  if (value == null) return undefined;
  if (typeof value === "string") return value;
  if (typeof value === "object") {
    try {
      const s = JSON.stringify(value);
      return s === "{}" ? undefined : s;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function normalize(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function formatReason(reason, details) {
  return details ? `${reason}: ${details}` : reason;
}

function findBlockedTerm(text, blockedTerms) {
  const lower = normalize(text);
  return blockedTerms.find((term) => lower.includes(term.toLowerCase())) || null;
}

function hasBlockedToolName(toolDefinition, blockedToolNames) {
  const toolName = normalize(toolDefinition?.name);
  return blockedToolNames.find((name) => toolName === name.toLowerCase()) || null;
}

function collectStringValues(value, results = []) {
  if (typeof value === "string") {
    results.push(value);
    return results;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectStringValues(item, results);
    }
    return results;
  }

  if (value && typeof value === "object") {
    for (const nestedValue of Object.values(value)) {
      collectStringValues(nestedValue, results);
    }
  }

  return results;
}

/**
 * Copilot Studio topics are surfaced to the planner as pseudo-tools and trigger the
 * analyze webhook, but they are not real external tool executions — Copilot fires them
 * even when the topics are disabled in the agent. They are identified by ".topic." in the
 * Copilot component id; real connector tools use ".action." (e.g.
 * "pub_UnderwriterCopilot.topic.BlockConfidentialDataExfiltration" vs
 * "pub_UnderwriterCopilot.action.UnderwriterCopilotTools-..._nAl").
 */
export function isCopilotTopicInvocation(toolDefinition) {
  const id = typeof toolDefinition?.id === "string" ? toolDefinition.id.toLowerCase() : "";
  return id.includes(".topic.");
}

export function computeBlockedFlags(payload, config = {}) {
  const blockedTerms = config.blockedTerms || [];
  const blockedToolNames = config.blockedToolNames || [];
  const plannerContext = payload?.plannerContext || {};
  const toolDefinition = payload?.toolDefinition || {};
  const inputParameters = payload?.inputParameters || [];

  const isBlockedTool = !!hasBlockedToolName(toolDefinition, blockedToolNames);
  const blockedTermInUserMessage = !!findBlockedTerm(plannerContext.userMessage, blockedTerms);

  const previousOutputs = plannerContext.previousToolOutputs || [];
  let blockedTermInPreviousOutput = false;
  for (const output of previousOutputs) {
    const values = collectStringValues(output);
    if (values.map((v) => findBlockedTerm(v, blockedTerms)).some(Boolean)) {
      blockedTermInPreviousOutput = true;
      break;
    }
  }

  let blockedTermInInput = false;
  for (const parameter of inputParameters) {
    const values = collectStringValues(parameter);
    if (values.map((v) => findBlockedTerm(v, blockedTerms)).some(Boolean)) {
      blockedTermInInput = true;
      break;
    }
  }

  return { isBlockedTool, blockedTermInUserMessage, blockedTermInPreviousOutput, blockedTermInInput };
}

export function evaluateToolExecution(payload, config = {}) {
  const blockedTerms = config.blockedTerms || [];
  const blockedToolNames = config.blockedToolNames || [];
  const plannerContext = payload?.plannerContext || {};
  const toolDefinition = payload?.toolDefinition || {};
  const inputParameters = payload?.inputParameters || [];

  const blockedToolName = hasBlockedToolName(toolDefinition, blockedToolNames);
  if (blockedToolName) {
    return {
      blockAction: true,
      reasonCode: REASON_CODE_BLOCKED_LOCAL_POLICY,
      reason: formatReason(
        "Blocked tool",
        `tool "${toolDefinition.name}" is disallowed by policy`
      ),
      details: {
        source: "local-policy",
        policy: "blockedToolNames",
        matchedValue: blockedToolName
      }
    };
  }

  const userMessageHit = findBlockedTerm(plannerContext.userMessage, blockedTerms);
  if (userMessageHit) {
    return {
      blockAction: true,
      reasonCode: REASON_CODE_BLOCKED_LOCAL_POLICY,
      reason: formatReason(
        "Blocked content in user message",
        `matched term "${userMessageHit}"`
      ),
      details: {
        source: "local-policy",
        policy: "blockedTerms",
        matchedValue: userMessageHit,
        field: "plannerContext.userMessage"
      }
    };
  }

  const previousOutputs = plannerContext.previousToolOutputs || [];
  for (const output of previousOutputs) {
    const values = collectStringValues(output);
    const hit = values.map((value) => findBlockedTerm(value, blockedTerms)).find(Boolean);
    if (hit) {
      return {
        blockAction: true,
        reasonCode: REASON_CODE_BLOCKED_LOCAL_POLICY,
        reason: formatReason(
          "Blocked content in previous tool output",
          `matched term "${hit}"`
        ),
        details: {
          source: "local-policy",
          policy: "blockedTerms",
          matchedValue: hit,
          field: "plannerContext.previousToolOutputs"
        }
      };
    }
  }

  for (const parameter of inputParameters) {
    const values = collectStringValues(parameter);
    const hit = values.map((value) => findBlockedTerm(value, blockedTerms)).find(Boolean);
    if (hit) {
      return {
        blockAction: true,
        reasonCode: REASON_CODE_BLOCKED_LOCAL_POLICY,
        reason: formatReason(
          "Blocked content in tool input",
          `parameter "${parameter.name}" matched term "${hit}"`
        ),
        details: {
          source: "local-policy",
          policy: "blockedTerms",
          matchedValue: hit,
          field: `inputParameters.${parameter.name || "unknown"}`
        }
      };
    }
  }

  return {
    blockAction: false,
    reason: "Allowed by default policy."
  };
}

/**
 * Microsoft AnalyzeToolExecutionResponse: blockAction (required), optional reasonCode, reason, diagnostics (string only).
 * See https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers
 */
export function createThreatResponse(result) {
  if (!result || typeof result !== "object") {
    return { blockAction: false };
  }

  if (!result.blockAction) {
    const out = { blockAction: false };
    if (result.reason) out.reason = result.reason;
    if (result.reasonCode != null && Number.isFinite(result.reasonCode)) {
      out.reasonCode = Math.trunc(result.reasonCode);
    }
    const diag =
      stringifyDiagnostics(result.diagnostics) ?? stringifyDiagnostics(result.details);
    if (diag) out.diagnostics = diag;
    return out;
  }

  const reasonCode =
    result.reasonCode != null && Number.isFinite(result.reasonCode)
      ? Math.trunc(result.reasonCode)
      : REASON_CODE_BLOCKED_LOCAL_POLICY;

  const out = {
    blockAction: true,
    reasonCode,
    reason: result.reason || DEFAULT_BLOCK_MESSAGE
  };
  const diag =
    stringifyDiagnostics(result.diagnostics) ?? stringifyDiagnostics(result.details);
  if (diag) out.diagnostics = diag;
  return out;
}

/**
 * Microsoft AnalyzeToolExecutionResponse allows only: blockAction, reasonCode, reason, diagnostics.
 * Strips any extra keys (e.g. accidental revaPdp) before sending JSON to Copilot.
 */
export function sanitizeMicrosoftAnalyzeResponse(body) {
  if (!body || typeof body !== "object") {
    return { blockAction: false };
  }
  const out = {};
  out.blockAction = body.blockAction === true;
  if (body.reasonCode != null && Number.isFinite(body.reasonCode)) {
    out.reasonCode = Math.trunc(body.reasonCode);
  }
  if (typeof body.reason === "string") out.reason = body.reason;
  if (typeof body.diagnostics === "string") out.diagnostics = body.diagnostics;
  return out;
}
