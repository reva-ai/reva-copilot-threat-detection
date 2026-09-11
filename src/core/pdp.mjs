import { REASON_CODE_BLOCKED_REVA_PDP } from "./policy.mjs";
import { hopIntent } from "./hop-intent.mjs";
import {
  buildMappingConfigFromEnv,
  resolveAgent,
  resolveTool,
  resolveUser,
  resolveUserGroups
} from "./mapping.mjs";
import {
  buildSessionBlock,
  buildTurnCollections,
  fitToBudget,
  resolveStartedAt,
  segment,
  SESSION_MAX_CHARS,
  SESSION_MAX_TURNS
} from "./turn.mjs";

/** Parse a JSON object env var into a plain map; {} on missing/invalid input. */
function parseJsonObjectEnv(raw) {
  if (!raw || typeof raw !== "string") return {};
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" && !Array.isArray(obj) ? obj : {};
  } catch {
    return {};
  }
}

function intEnv(raw, fallback) {
  const n = Number.parseInt(String(raw ?? ""), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export function buildRevaPdpConfigFromEnv(env = process.env) {
  const t = (k) => env[k] === "true" || env[k] === "1";
  return {
    pdpUrl: env.REVA_PDP_URL || "",
    policyStoreId: env.REVA_POLICY_STORE_ID || "",
    pdpToken: env.REVA_PDP_TOKEN || "",
    /** Optional Origin header for the Reva gateway. Only sent when set. */
    pdpOrigin: env.REVA_PDP_ORIGIN || "",
    /** Kept for backward compatibility; the full map set lives on `mapping`. */
    principalIdMap: parseJsonObjectEnv(env.REVA_PRINCIPAL_ID_MAP),
    mapping: buildMappingConfigFromEnv(env),
    /** When true, enrich reason and embed the PDP's own text in diagnostics. */
    surfacePdpResponse: t("REVA_PDP_SURFACE_RESPONSE") || t("REVA_PDP_PASS_THROUGH"),
    /**
     * Microsoft's budget is ~1s and it fails OPEN on timeout, so this bound is a real
     * policy choice rather than a formality: too tight denies work the PDP was about to
     * allow, too loose lets Copilot proceed unauthorized before we answer.
     *
     * Measured against a live deployment, evaluation returns in ~150-250ms warm with
     * guardrails deferred — the default posture, and comfortably inside the budget. The
     * default here is generous because of the slow cases, not the normal one: a cold
     * container, and inline guardrail evaluation in enforce mode, which costs materially
     * more per call and has been seen at 2.6-3.0s.
     */
    timeoutMs: intEnv(env.REVA_PDP_TIMEOUT_MS, 2500),
    /** Debug only. Fail closed is the default: an unreachable PDP still blocks the turn. */
    failOpen: t("REVA_FAIL_OPEN"),
    /**
     * `monitor` (or `log`) evaluates for real and records the verdict, then lets the call
     * through anyway. It is how a rollout starts: run production Copilot traffic against
     * real policy, read what WOULD have been refused, then switch to `enforce`.
     *
     * Deliberately separate from REVA_FAIL_OPEN, which governs the case where we could not
     * get a decision at all. This one governs a decision we did get and chose not to act on;
     * conflating them would mean you could not watch policy without also disarming the
     * outage path. Spelling matches the LiteLLM (REVA_HOOK_MODE) and TrueFoundry (mode)
     * plugins, which already take enforce | log | monitor.
     */
    monitorMode: ["monitor", "log"].includes(String(env.REVA_MODE || "enforce").toLowerCase()),
    /**
     * Refuse when the end user is not in conversationMetadata, rather than falling back to
     * the transport identity. Off by default: the fallback is the deployed behaviour, and a
     * delegated test token legitimately carries the caller.
     */
    requireBodyPrincipal: t("REVA_REQUIRE_BODY_PRINCIPAL"),
    /**
     * The policy store namespaces run-time attributes with the store name (spaces and
     * underscores stripped, casing kept, "_" appended). Cedar matches context keys by exact
     * name and a missing key is NOT an error — it fails the `has` guard, so a wrong prefix
     * means the policy publishes and never fires. Empty preserves the deployed v1 behaviour.
     */
    contextAttrPrefix: env.REVA_CONTEXT_ATTR_PREFIX || "",
    /**
     * The schema's OWN context attributes (timestamp, sourceIp, environment), sent under
     * their declared names with no prefix. The four blocked-term flags that used to live
     * here were removed: no policy referenced them, and they were never in the schema.
     */
    sendSchemaContext: env.REVA_SEND_SCHEMA_CONTEXT !== "false",
    /** Copilot environment GUID -> the schema enum PROD | STAGING | DEV | SANDBOX. */
    environmentMap: parseJsonObjectEnv(env.REVA_ENVIRONMENT_MAP),
    /**
     * Copilot metadata an open policy can test — tenant, channel, environment, published
     * state, tool type. On by default: they are additive context keys, and Cedar ignores a
     * key no policy mentions, so a store that does not use them is unaffected.
     */
    sendCopilotContext: env.REVA_SEND_COPILOT_CONTEXT !== "false",
    includePlannerThought: env.REVA_INCLUDE_PLANNER_THOUGHT !== "false",
    sessionMaxTurns: intEnv(env.REVA_SESSION_MAX_TURNS, SESSION_MAX_TURNS),
    sessionMaxChars: intEnv(env.REVA_SESSION_MAX_CHARS, SESSION_MAX_CHARS)
  };
}

export function isRevaPdpConfigured(config) {
  return Boolean(config.pdpUrl && config.policyStoreId && config.pdpToken);
}

function normalizePlannerContext(payload) {
  const raw =
    payload?.plannerContext && typeof payload.plannerContext === "object" ? payload.plannerContext : {};
  const previousToolOutputs = Array.isArray(raw.previousToolOutputs)
    ? raw.previousToolOutputs
    : Array.isArray(raw.previousToolsOutputs)
      ? raw.previousToolsOutputs
      : [];
  return { ...raw, previousToolOutputs };
}

/**
 * W3C traceparent. The trace-id derives from the CONVERSATION id so every decision in one
 * chat shares a trace; the span-id from the per-request correlation id. Without it the PDP
 * starts a fresh trace and the decision rows for a turn scatter — and those rows only mean
 * anything read together.
 */
function buildTraceparent(conversationId, correlationId) {
  const hexOnly = (s) => String(s || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  const traceSrc = hexOnly(conversationId) || hexOnly(correlationId);
  if (traceSrc.length < 8) return null;
  const traceId = traceSrc.slice(0, 32).padEnd(32, "0");
  const spanSrc = hexOnly(correlationId);
  const spanId = (spanSrc.slice(0, 16) || "0000000000000001").padEnd(16, "0");
  return `00-${traceId}-${spanId}-01`;
}

function extractInputValues(payload) {
  if (payload?.inputValues && typeof payload.inputValues === "object" && !Array.isArray(payload.inputValues)) {
    return payload.inputValues;
  }
  return Object.fromEntries(
    (payload?.inputParameters || [])
      .filter((p) => p && typeof p.name === "string")
      .map((p) => [p.name, p.value])
  );
}

/**
 * Builds a Reva Evaluation API v2 request (POST /pdp/v2/ai/evaluation).
 *
 * `context` takes flat scalars, scalar arrays, and records ONLY from a fixed allowlist.
 * Anything else is rejected outright, naming the offending key:
 *   400 invalid Cedar context: managed context records are not supported
 *       at managed context.<key>
 *
 * Probed against pr06 on 2026-09-10, one key at a time:
 *   conversation, hops, chatHistory   accepted (structured, and what we send)
 *   environment, onBehalfOf           ACCEPTED — both are on the allowlist
 *   chain, and any other record       400
 *   flat scalars, scalar arrays       accepted
 *
 * Note the middle row, because an earlier revision of this file asserted the opposite and
 * said sending those two "would have denied every call on v2". They do not.
 *
 * `onBehalfOf` is still not sent, because it is projected server-side from `principal` and
 * appears in the decision log without us sending it.
 *
 * `environment` IS sent, when REVA_ENVIRONMENT_MAP supplies a value. An earlier note here
 * called it unusable in a policy; the store schema disproves that — it is a declared context
 * attribute of type String with the enum PROD | STAGING | DEV | SANDBOX. What was wrong on
 * v1 was the SHAPE: v1 sent a Record (`{requestId, time, sourceIp, traceparent}`) where the
 * schema wants one of four strings, so no policy could ever have matched it.
 *
 * Entity IDS are free-form — nothing has to be registered in the store first. Entity TYPES
 * and ACTIONS are schema-bound and are checked:
 *   resource {type:"Widget"}  -> 403 invokeTool requires a Tool resource, resolved "Widget"
 *   action   "frobnicate"     -> 403 Tool resource requires action invokeTool
 */
export function buildPdpRequest(payload, authResult, correlationId, options = {}) {
  const plannerContext = normalizePlannerContext(payload);
  const toolDefinition = payload?.toolDefinition || {};
  const principal = authResult?.principal || {};
  const meta =
    payload?.conversationMetadata && typeof payload.conversationMetadata === "object"
      ? payload.conversationMetadata
      : {};
  const agent = meta.agent && typeof meta.agent === "object" ? meta.agent : {};
  const mapping = options.mapping || { users: {}, agents: {}, tools: {}, userGroups: {} };
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();

  // The principal is the originating END USER, never the Entra transport identity and never
  // the agent, however deep the chain.
  //
  // Microsoft's BODY is preferred over the verified token here, which looks backwards and is
  // not. The bearer token authenticates Power Platform calling us, and under the federated
  // credential of INSTALL.md §4.2 that is an app identity: its `oid` is the service
  // principal, not the person who typed. conversationMetadata.user.id is the only place the
  // end user appears, and it arrives over a channel we authenticated. Preferring the token
  // would substitute "Power Platform" for "alice" and authorize the wrong subject — the
  // token's claims are a LAST resort, kept only for a delegated test token.
  //
  // Which source answered is recorded on every event, because "the wrong principal" is
  // otherwise indistinguishable from "the right principal with wrong policies".
  const metaUserId = meta.user?.id;
  const rawUserId = metaUserId || principal.oid || principal.sub || "unknown";
  const principalSource = metaUserId
    ? "conversation-metadata"
    : principal.oid
      ? "token-oid"
      : principal.sub
        ? "token-sub"
        : "none";
  const userRes = resolveUser(rawUserId, mapping);
  const agentRes = resolveAgent(agent, mapping);
  const toolRes = resolveTool(toolDefinition, mapping);

  const agentName = agent.name || agent.id || "unknown-agent";
  const toolName = toolDefinition.name || toolDefinition.id || "unknown-tool";
  const inputValues = extractInputValues(payload);

  const seg = segment(plannerContext, { nowMs });
  const { messages, hops } = buildTurnCollections(seg.current, {
    userId: userRes.id,
    agentId: agentRes.id,
    // Past tool hops go through the same mapping as the current one.
    resolveToolId: (name, id) => resolveTool({ name, id }, mapping).id
  });

  const startedAtMs = resolveStartedAt(seg.chat, seg.tools, nowMs);
  const session = buildSessionBlock(seg.priorTurns, {
    sessionId: meta.conversationId || meta.planId || correlationId || "",
    startedAtMs,
    maxTurns: options.sessionMaxTurns,
    maxChars: options.sessionMaxChars
  });

  // Entry-hop rule: with nothing yet said, send an EMPTY context rather than hops beside an
  // empty conversation. Do not state the current turn twice — transmission.content has it.
  const context = {};
  if (messages.length) {
    context.conversation = { messages };
    context.hops = hops;
  }

  // Context splits in two, and the difference is what the PREFIX is for.
  //
  // The schema declares its own context attributes for invokeTool — onBehalfOf, chain,
  // timestamp, sourceIp, geo, network, environment and so on. Those are the platform's
  // names and are written verbatim: prefixing one would invent an attribute nobody
  // declared. The prefix belongs only to attributes an operator ADDS to their store, which
  // the platform namespaces as `<StoreName>_<attr>`.
  //
  // Attributes the schema does not know are accepted and ignored (verified against pr06 on
  // 2026-09-10: a context full of undeclared keys evaluates normally). So sending a superset
  // is safe; the schema only decides what a policy can be WRITTEN against. `required` in the
  // schema is checked when ingesting entity data, not when evaluating — per Reva, the PDP
  // evaluates whatever arrives and a policy fires if its attributes are present. That is why
  // `chain` being both required and refused by this API is survivable rather than fatal.
  const prefix = options.contextAttrPrefix || "";

  // --- schema-declared, therefore UNPREFIXED ---
  if (options.sendSchemaContext !== false) {
    // Long. Declared required, and cheap to satisfy. Milliseconds — see envars.md; a policy
    // comparing against it has to agree about the unit, and the schema does not say.
    context.timestamp = nowMs;

    const sourceIp = meta.incomingClientIp;
    if (typeof sourceIp === "string" && sourceIp !== "") context.sourceIp = sourceIp;

    // The schema's `environment` is the enum PROD | STAGING | DEV | SANDBOX, NOT the record
    // v1 used to send — that mismatch, not any prohibition, is why the v1 shape was wrong.
    // Copilot only gives us an environment GUID, so the mapping has to be supplied.
    const env = options.environmentMap?.[agent.environmentId];
    if (typeof env === "string" && env !== "") context.environment = env;
  }

  // --- ours, therefore PREFIXED ---
  //
  // A store built on named-entity policies asks "is this amit calling fetch-risk-score?",
  // which needs both registered. A store written openly asks "may any agent call this tool,
  // given the circumstances?" — and the circumstances have to be in the payload or the rule
  // has nothing to test. These are the discriminators Copilot gives us that a reviewer would
  // plausibly write a rule about:
  //
  //   permit(...) when { context.MyStore_agentIsPublished == true };   // no draft agents
  //   forbid(...) when { context.MyStore_channelId == "pva-studio" };  // not from the editor
  //
  // Flat scalars, because context takes records only from a fixed allowlist. Nothing here is
  // prompt text or user content — ids, a channel name and a boolean.
  if (options.sendCopilotContext !== false) {
    const scalars = {
      tenantId: meta.user?.tenantId || meta.agent?.tenantId,
      channelId: meta.channelId,
      agentEnvironmentId: agent.environmentId,
      agentIsPublished: agent.isPublished,
      // NOT `toolType`: the schema already has Tool.toolType as an ENTITY attribute, whose
      // values are MCP | OPENAPI | FUNCTION | ... Microsoft's is a different thing entirely
      // ("CustomConnectorToolDefinition"), and one name for two value spaces is a trap for
      // whoever writes the policy.
      copilotToolType: toolDefinition.type
    };
    for (const [key, value] of Object.entries(scalars)) {
      if (typeof value === "string" && value !== "") context[`${prefix}${key}`] = value;
      else if (typeof value === "boolean") context[`${prefix}${key}`] = value;
    }
  }

  // Cedar entity data supplied WITH the request, which is how a policy gets to say
  // `principal in UserGroup::"Underwriters"` without every user being registered in the
  // store. The Kong plugin does exactly this and reads the groups off a JWT claim; here they
  // come from configuration, because Copilot's bearer token authenticates Power Platform and
  // says nothing about the person. No groups configured => no `entities` key => the payload
  // is byte-identical to what it was before this existed.
  //
  // Only the User is declared. Sending attributes for the Agent or Tool was tested and
  // accepted, but entity ATTRIBUTES are schema-defined in a way ids are not, and an
  // attribute the schema does not know is the classic silent-drop trap — so that stays out
  // until it can be checked against a store's actual schema.
  const userGroups = resolveUserGroups(rawUserId, userRes.id, mapping);
  const entities =
    userGroups.length > 0
      ? [
          {
            uid: { type: "User", id: userRes.id },
            parents: userGroups.map((group) => ({ type: "UserGroup", id: group }))
          }
        ]
      : undefined;

  const body = {
    subject: { type: "Agent", id: agentRes.id, name: agentName },
    action: { name: "invokeTool" },
    resource: { type: "Tool", id: toolRes.id, name: toolName },
    principal: { type: "User", id: userRes.id },
    context,
    transmission: {
      promptKey: "content",
      // "agent" because an agent is what is speaking here. This said "user" on v1 while
      // `subject` on the same payload said Agent — and a user instruction is authoritative,
      // it SETS intent rather than being measured against it, so labelling the agent's own
      // decision "user" made ALIGNED correct however far the agent had wandered.
      role: "agent",
      contentType: "text/plain",
      // What THIS hop does, never the user's prompt — a hop compared against itself is
      // always ALIGNED.
      content: hopIntent(toolDefinition, inputValues, {
        thought: plannerContext.thought,
        includeThought: options.includePlannerThought !== false
      }),
      response: ""
    },
    inputValues,
    session,
    ...(entities ? { entities } : {})
  };

  return {
    body,
    resolutions: { user: userRes, agent: agentRes, tool: toolRes },
    principalSource,
    shape: {
      conversation: messages.length,
      hops: hops.length,
      sessionTurn: session.turn,
      sessionMessages: session.messages?.length || 0,
      anchorSynthetic: seg.current.anchorIsSynthetic
    }
  };
}

function extractDecisionField(pdpResponse) {
  if (!pdpResponse || typeof pdpResponse !== "object") return undefined;
  if (Object.prototype.hasOwnProperty.call(pdpResponse, "decision")) return pdpResponse.decision;
  if (typeof pdpResponse.cedarDecision === "boolean") return pdpResponse.cedarDecision;
  if (typeof pdpResponse.isAllowed === "boolean") return pdpResponse.isAllowed;
  return undefined;
}

const PDP_REASON_STRING_KEYS = [
  "reason",
  "message",
  "explanation",
  "denyReason",
  "policyReason",
  "errorMessage",
  "description",
  "userMessage"
];

function firstNonemptyStringFromObject(obj, keys) {
  if (!obj || typeof obj !== "object") return "";
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
    const v = obj[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

function extractPdpReasonText(pdpResponse) {
  const fromContext = firstNonemptyStringFromObject(pdpResponse?.context, PDP_REASON_STRING_KEYS);
  if (fromContext) return fromContext;
  return firstNonemptyStringFromObject(pdpResponse, PDP_REASON_STRING_KEYS);
}

function extractPdpReasonCode(pdpResponse) {
  const c = pdpResponse?.reasonCode ?? pdpResponse?.code;
  if (typeof c === "number" && Number.isFinite(c)) return Math.trunc(c);
  if (typeof c === "string" && /^\d+$/.test(c.trim())) return parseInt(c.trim(), 10);
  return undefined;
}

function mapPdpResponse(pdpResponse, policyStoreId, pdpConfig, toolName) {
  const d = extractDecisionField(pdpResponse);
  const allowed = d === true || d === "true" || d === "allow" || d === "Allow" || d === "ALLOW";

  const surface = Boolean(pdpConfig?.surfacePdpResponse);
  const pdpReason = surface ? extractPdpReasonText(pdpResponse) : "";
  const slimMeta = { source: "reva-pdp", policyStoreId, ...(toolName ? { toolName } : {}) };

  if (allowed) {
    const reason = surface && pdpReason ? pdpReason : "Allowed by Reva PDP policy.";
    const out = { blockAction: false, reason };
    const optionalCode = extractPdpReasonCode(pdpResponse);
    if (optionalCode != null) out.reasonCode = optionalCode;
    if (surface) out.details = slimMeta;
    return out;
  }

  const reason =
    surface && pdpReason
      ? pdpReason
      : surface
        ? `Blocked by Reva authorization policy. (${String(d)})`
        : "Blocked by Reva authorization policy.";

  return {
    blockAction: true,
    reason,
    reasonCode: extractPdpReasonCode(pdpResponse) ?? REASON_CODE_BLOCKED_REVA_PDP,
    details: slimMeta
  };
}

/**
 * A connection that died mid-flight, as opposed to one that was refused or never resolved.
 * fetch wraps the real error as `cause`, so the code is one level down.
 */
const RETRYABLE_SOCKET_CODES = new Set([
  "ECONNRESET",
  "EPIPE",
  "ECONNABORTED",
  "UND_ERR_SOCKET"
]);

function socketErrorCode(err) {
  return err?.cause?.code || err?.code || null;
}

function isRetryableSocketError(err) {
  return RETRYABLE_SOCKET_CODES.has(socketErrorCode(err));
}

function safePdpUrlParts(pdpUrl) {
  try {
    const u = new URL(pdpUrl);
    return { host: u.host, pathname: u.pathname };
  } catch {
    return { host: "", pathname: "" };
  }
}

/** Safe subset for client responses and DynamoDB observability (no tokens, no prompt text). */
export function summarizePdpDiagnostics(d) {
  if (!d || typeof d !== "object") return {};
  return {
    policyStoreId: d.policyStoreId,
    pdpHost: d.pdpHost,
    pdpPath: d.pdpPath,
    latencyMs: d.latencyMs,
    httpStatus: d.httpStatus,
    rawDecision: d.rawDecision,
    pdpReason: d.pdpReason,
    error: d.error,
    errorKind: d.errorKind,
    toolName: d.toolName,
    // Names and counts only — safe to leave on, which is the point. A conversation/hops
    // divergence is a defect, and this is the cheapest place to see it.
    payloadShape: d.payloadShape,
    entityResolution: d.entityResolution,
    trimSteps: d.trimSteps,
    attempts: d.attempts,
    retriedAfter: d.retriedAfter,
    responsePreview:
      typeof d.responsePreview === "string" && d.responsePreview.length > 400
        ? `${d.responsePreview.slice(0, 400)}…`
        : d.responsePreview || null
  };
}

/**
 * Calls the Reva PDP and returns a policy mapping plus diagnostics.
 * On transport/HTTP/parse/config failure, ok is false and policyResult is null — the caller
 * decides fail-open vs fail-closed. `errorKind` distinguishes a configuration fault from an
 * outage, because "blocked by policy" sends the reader to Cedar and "cannot reach the
 * authorization service" sends them to their config; the wrong one costs a day.
 */
export async function evaluateViaRevaPdp(payload, pdpConfig, authResult, correlationId) {
  const { pdpUrl, policyStoreId, pdpToken, pdpOrigin } = pdpConfig;
  const started = Date.now();
  const urlParts = safePdpUrlParts(pdpUrl);

  const diagnostics = {
    policyStoreId,
    pdpHost: urlParts.host,
    pdpPath: urlParts.pathname,
    latencyMs: 0,
    httpStatus: null,
    responsePreview: null,
    rawDecision: null,
    pdpReason: null,
    error: null,
    errorKind: null,
    toolName: payload?.toolDefinition?.name || null,
    payloadShape: null,
    entityResolution: null,
    trimSteps: [],
    attempts: 0,
    retriedAfter: null
  };

  const conversationId = payload?.conversationMetadata?.conversationId || "";
  const traceparent = buildTraceparent(conversationId, correlationId);

  let built;
  try {
    built = buildPdpRequest(payload, authResult, correlationId, {
      mapping: pdpConfig.mapping,
      contextAttrPrefix: pdpConfig.contextAttrPrefix,
      sendSchemaContext: pdpConfig.sendSchemaContext,
      environmentMap: pdpConfig.environmentMap,
      sendCopilotContext: pdpConfig.sendCopilotContext,
      includePlannerThought: pdpConfig.includePlannerThought,
      sessionMaxTurns: pdpConfig.sessionMaxTurns,
      sessionMaxChars: pdpConfig.sessionMaxChars
    });
  } catch (err) {
    diagnostics.latencyMs = Date.now() - started;
    diagnostics.error = err instanceof Error ? err.message : String(err);
    diagnostics.errorKind = "payload-build";
    return { ok: false, policyResult: null, diagnostics };
  }

  diagnostics.payloadShape = built.shape;
  diagnostics.entityResolution = {
    user: `${built.principalSource}:${built.resolutions.user.via}`,
    agent: `${built.resolutions.agent.via}:${built.resolutions.agent.id}`,
    tool: `${built.resolutions.tool.via}:${built.resolutions.tool.id}`
  };

  // Anything but conversation-metadata means the end user was not in Microsoft's payload and
  // we fell back to the transport identity, which under the production federated credential
  // is Power Platform's service principal rather than a person. That authorizes the wrong
  // subject while looking entirely healthy, so operators who have seen it once can refuse it.
  if (pdpConfig.requireBodyPrincipal && built.principalSource !== "conversation-metadata") {
    diagnostics.latencyMs = Date.now() - started;
    diagnostics.error = `End user absent from conversationMetadata (principal came from ${built.principalSource})`;
    diagnostics.errorKind = "no-principal";
    return { ok: false, policyResult: null, diagnostics };
  }

  const { body, trimSteps } = fitToBudget(built.body);
  diagnostics.trimSteps = trimSteps;

  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${pdpToken}`,
    policyStoreId
  };
  if (pdpOrigin) headers.origin = pdpOrigin;
  if (correlationId) headers["x-ms-correlation-id"] = correlationId;
  if (traceparent) headers.traceparent = traceparent;

  const budgetMs = pdpConfig.timeoutMs || 2500;
  // ONE deadline for the whole operation, not one per attempt. Microsoft's budget is about a
  // second and it fails open past its own; a retry that restarts the clock would let two
  // attempts run to 2 × timeoutMs and hand Copilot an unauthorized allow while we were still
  // asking. Whatever we do, we are done by `deadline`.
  const deadline = started + budgetMs;

  let response = null;
  let attempts = 0;

  for (;;) {
    attempts += 1;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      diagnostics.latencyMs = Date.now() - started;
      diagnostics.attempts = attempts - 1;
      diagnostics.error = `PDP timed out after ${budgetMs}ms`;
      diagnostics.errorKind = "timeout";
      return { ok: false, policyResult: null, diagnostics };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    try {
      response = await fetch(pdpUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal
      });
      break;
    } catch (err) {
      const aborted = err?.name === "AbortError";

      // Retry ONLY a socket that died under us, and only once. A pooled connection the peer
      // closed while we were idle fails instantly and succeeds on a second try, and on a
      // fail-closed path that failure blocks a legitimate tool call. Everything else is left
      // alone on purpose: a timeout has already spent the budget, and a refused connection or
      // failed DNS means the service is down, where an immediate retry only adds latency to
      // an answer we already have.
      if (!aborted && attempts === 1 && isRetryableSocketError(err) && Date.now() < deadline) {
        diagnostics.retriedAfter = socketErrorCode(err);
        continue;
      }

      diagnostics.latencyMs = Date.now() - started;
      diagnostics.attempts = attempts;
      diagnostics.error = aborted
        ? `PDP timed out after ${budgetMs}ms`
        : err instanceof Error
          ? err.message
          : String(err);
      diagnostics.errorKind = aborted ? "timeout" : "transport";
      return { ok: false, policyResult: null, diagnostics };
    } finally {
      clearTimeout(timer);
    }
  }

  diagnostics.attempts = attempts;

  try {
    diagnostics.httpStatus = response.status;
    diagnostics.latencyMs = Date.now() - started;

    const bodyText = await response.text().catch(() => "<unreadable>");
    diagnostics.responsePreview = bodyText.length > 1200 ? `${bodyText.slice(0, 1200)}…` : bodyText;

    let parsed = null;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      parsed = null;
    }

    const firstResult = Array.isArray(parsed) ? parsed[0] : parsed;
    const decisionField =
      firstResult && typeof firstResult === "object" ? extractDecisionField(firstResult) : undefined;

    // The Evaluation API returns 200 for allow and 403 for deny, both carrying a `decision`
    // body. A 403 deny is a block, not a transport failure.
    //
    // But a decision is only authoritative on those two statuses. Anything else is a fault
    // EVEN WHEN it carries `decision:false` — verified against pr06 on 2026-09-10, where a
    // body the API rejects answers:
    //   400 {"decision":false,"context":{"reason":"invalid session: ..."}}
    // Reading that as a decision reported OUR OWN malformed request to Copilot as
    // reasonCode 101, "Blocked by Reva authorization policy", which sends whoever debugs it
    // into Cedar hunting a rule that does not exist. The status is the only thing that
    // separates "the policy said no" from "we asked the question wrong".
    // 403 is overloaded, so the status alone is not enough. Probed on pr06 2026-09-10:
    //
    //   real Cedar denial      403  error_type "POLICY_DENIED"  "authorization denied by policy"
    //   wrong entity type      403  (no error_type)             "...requires a Tool resource..."
    //   wrong action           403  (no error_type)             "...requires action invokeTool"
    //   malformed session/ctx  400  (no error_type)
    //
    // The last three are OUR payload being wrong. `error_type` is the only positive signal
    // that a 403 is a decision rather than a rejection, so it is what we key on.
    //
    // If Reva ever stops emitting the field, real denials degrade to "invalid-payload":
    // still blocked, still fail-closed, reasonCode 103 instead of 101, and the event still
    // carries the PDP's own "authorization denied by policy" — a wrong label, never a wrong
    // decision. That is the safe direction to be wrong in, and the reverse (calling our own
    // bad request a policy deny) is the failure this whole path exists to prevent.
    const isPolicyDecision =
      response.ok || (response.status === 403 && firstResult?.error_type === "POLICY_DENIED");

    if (!isPolicyDecision) {
      // The PDP answers JSON on every status it owns — allow, deny, and the rejections it
      // issues for a payload it dislikes. A NON-JSON error body therefore did not come from
      // the PDP at all: something in front of it answered instead, and the request never
      // arrived.
      //
      // Observed in a real deployment: an AWS WAF on the CDN in front of the PDP answers
      // with the CDN's own error page —
      //   403  text/html  "403 ERROR ... The request could not be satisfied. Request blocked."
      // carrying `x-cache: Error from cloudfront` and NO `x-amzn-requestid`, i.e. it never
      // reached the gateway — for any body matching its SQLi/XSS/LFI signatures inside the
      // first ~16 KB. `<script>`, `' OR 1=1 --` and `../../../../etc/passwd` each trip it;
      // the same strings past 16 KB do not, so the block is also position-dependent.
      //
      // That is not an edge case for this service, it is the normal case: the payload we
      // forward is attacker-controlled BY DESIGN — user prompts, tool outputs, fetched
      // documents — so content-pattern rules on this path fire on precisely the traffic the
      // guardrails exist to score. Calling it "invalid-payload" blames our own request
      // builder and sends whoever is on the pager to the wrong team, so an upstream block
      // gets a kind of its own that names the intermediary.
      // 401 is excluded on purpose, whatever the body looks like. No content-matching WAF
      // rule answers 401, and per this project's notes the usual cause is a token scoped to
      // the wrong path family or host — "check the credentials" stays the right instruction
      // even if some intermediary is the one saying it. A genuine PDP 401 is JSON
      // ({"error":"Unauthorized","status":401,...}), so in practice
      // the two rules do not overlap; this ordering just makes the tie-break deliberate.
      const upstreamBlocked =
        response.status !== 401 &&
        parsed === null &&
        bodyText.trim() !== "" &&
        bodyText !== "<unreadable>";

      if (upstreamBlocked) {
        const contentType = response.headers.get("content-type") || "no content-type";
        const server = response.headers.get("server");
        diagnostics.error =
          `HTTP ${response.status}: blocked before reaching the PDP — non-JSON body ` +
          `(${contentType}${server ? `, server: ${server}` : ""})`;
        diagnostics.errorKind = "upstream-blocked";
      } else {
        const reason = extractPdpReasonText(firstResult);
        diagnostics.error = reason ? `HTTP ${response.status}: ${reason}` : `HTTP ${response.status}`;
        diagnostics.errorKind =
          response.status === 401 ? "auth" : response.status < 500 ? "invalid-payload" : "protocol";
      }
      // Recorded so the observability event shows what the PDP actually said, even though
      // we are deliberately not treating it as a decision.
      diagnostics.rawDecision = decisionField ?? null;
      return { ok: false, policyResult: null, diagnostics };
    }

    // Only a response we already accepted as a decision reaches here: a 2xx, or a 403 that
    // declared itself POLICY_DENIED. Either way a missing `decision` is the API contradicting
    // itself, which is a protocol fault — 401 and non-policy 403s were classified above.
    if (decisionField === undefined) {
      diagnostics.error = parsed
        ? "Response missing decision field"
        : "Invalid JSON in PDP response";
      diagnostics.errorKind = "protocol";
      return { ok: false, policyResult: null, diagnostics };
    }

    diagnostics.rawDecision = decisionField ?? null;
    // The PDP's own words, recorded whatever REVA_PDP_SURFACE_RESPONSE says. That flag
    // governs what we tell COPILOT, an external surface; this is the internal event, which
    // already carries responsePreview, so there is nothing extra exposed here. Monitor mode
    // depends on it: "something would have been denied" without the reason is not a finding.
    diagnostics.pdpReason = extractPdpReasonText(firstResult) || null;
    const toolName = payload?.toolDefinition?.name || "";
    const policyResult = mapPdpResponse(firstResult, policyStoreId, pdpConfig, toolName);
    return { ok: true, policyResult, diagnostics };
  } catch (err) {
    // Reading the response, not making the request — a retry would not help.
    diagnostics.latencyMs = Date.now() - started;
    diagnostics.error = err instanceof Error ? err.message : String(err);
    diagnostics.errorKind = "protocol";
    return { ok: false, policyResult: null, diagnostics };
  }
}
