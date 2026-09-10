/**
 * Reconstructs Reva's turn model from ONE Microsoft Copilot Studio webhook payload.
 *
 * Microsoft fires /analyze-tool-execution only for candidate agent -> tool calls, so the
 * user -> agent entry hop and every earlier turn have to be recovered from
 * plannerContext.chatHistory (newest-first) and plannerContext.previousToolsOutputs
 * (which span multiple turns).
 *
 * THE LOAD-BEARING RULE: build one ordered `events` list, apply every filter, replacement
 * and trim to THAT list, then emit context.conversation.messages and context.hops together
 * in a single pass. The contract's invariant — conversation.length === hops.length on every
 * hop — is then unreachable-by-construction rather than something we check afterwards.
 * The previous builder emitted the two arrays from separate loops with different guards and
 * diverged whenever a tool output had no toolName or an empty value.
 */

import { hopIntentFromName } from "./hop-intent.mjs";

/** Replaces our own prior block messages. See normalizeChat() for why. */
export const GATEWAY_MARKER = "[reva-gateway] The previous request was blocked by policy.";

const DEFAULT_GATEWAY_PATTERNS = [
  /Reva Trust Gateway/i,
  /Request Blocked/i,
  /Matched term\s*:/i,
  /Enforced by\s*:\s*Reva/i
];

export const SESSION_MAX_TURNS = 10;
export const SESSION_MAX_CHARS = 2000;
export const RESPONSE_MAX_CHARS = 4000;
export const CURRENT_EVENT_MAX = 50;
/** Tolerance when bucketing a tool output whose clock disagrees with chatHistory's. */
export const SKEW_MS = 2000;

const TRUNCATION_MARKER = " … [truncated]";
/** .NET emits 7-digit fractional seconds; Date.parse wants at most 3. */
const DOTNET_FRACTION = /(\.\d{3})\d+(Z|[+-]\d{2}:?\d{2})?$/;

// ---------------------------------------------------------------------------
// timestamps
// ---------------------------------------------------------------------------

/**
 * null means UNKNOWN and stays null. The previous builder returned 0 for unparseable
 * input, which sorted bad timestamps to the front of the chronology and silently
 * reordered the journey the drift evaluator reads.
 */
export function parseTs(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value > 1e12) return value;
    if (value > 1e9) return value * 1000;
    return null;
  }
  if (typeof value !== "string" || !value.trim()) return null;
  const n = Date.parse(value.trim().replace(DOTNET_FRACTION, "$1$2"));
  return Number.isFinite(n) ? n : null;
}

/** Second precision, matching the contract's own sample payloads. */
export function isoSec(ms) {
  const n = Number.isFinite(ms) ? ms : Date.now();
  return new Date(n).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function clampChars(text, max) {
  const s = String(text == null ? "" : text);
  return s.length > max ? s.slice(0, max) + TRUNCATION_MARKER : s;
}

// ---------------------------------------------------------------------------
// normalisation
// ---------------------------------------------------------------------------

/** Adaptive cards and similar arrive as objects; coerce rather than drop. */
function toText(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

/** Microsoft ToolExecutionOutput.outputs ([{name,value}]) -> compact {name: value} JSON. */
export function serializeToolOutputs(outputs) {
  if (outputs == null) return "";
  if (typeof outputs === "string") return outputs;
  if (Array.isArray(outputs)) {
    const obj = {};
    for (const o of outputs) {
      if (o && typeof o === "object" && typeof o.name === "string") obj[o.name] = o.value;
    }
    return toText(obj) === "{}" ? "" : toText(obj);
  }
  return toText(outputs);
}

function normalizeRole(role) {
  const r = String(role || "").toLowerCase();
  if (r === "user" || r === "human") return "user";
  if (r === "system" || r === "developer") return "drop";
  return "assistant";
}

/**
 * chatHistory is newest-first; reverse to chronological. Array order is authoritative —
 * timestamps are used only to interleave tool outputs and to bucket turns.
 *
 * Our own prior block messages arrive here as assistant turns quoting the matched term.
 * They are REPLACED rather than kept or dropped: keeping them re-injects the blocked term
 * into every later payload (a term policy then fires on our own enforcement text and wedges
 * the chat), while dropping them hides the highest-value trajectory signal there is —
 * asked, refused, reworded.
 */
export function normalizeChat(chatHistory, gatewayPatterns = DEFAULT_GATEWAY_PATTERNS) {
  const raw = Array.isArray(chatHistory) ? chatHistory : [];
  const chronological = raw.slice().reverse();
  const out = [];
  for (const m of chronological) {
    if (!m || typeof m !== "object") continue;
    const role = normalizeRole(m.role);
    if (role === "drop") continue;
    const text = toText(m.content);
    if (!text.trim()) continue;
    const gateway = role === "assistant" && gatewayPatterns.some((re) => re.test(text));
    out.push({
      kind: "chat",
      role,
      text: gateway ? GATEWAY_MARKER : text,
      gateway,
      ms: parseTs(m.timestamp),
      ord: out.length
    });
  }
  return out;
}

export function normalizeTools(previousToolOutputs) {
  const raw = Array.isArray(previousToolOutputs) ? previousToolOutputs : [];
  return raw
    .filter((t) => t && typeof t === "object")
    .map((t, i) => ({
      kind: "tool",
      toolName: typeof t.toolName === "string" ? t.toolName : "",
      toolId: typeof t.toolId === "string" ? t.toolId : "",
      text: serializeToolOutputs(t.outputs),
      ms: parseTs(t.timestamp),
      ord: i
    }));
}

function sameText(a, b) {
  const norm = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 512);
  return norm(a) === norm(b) && norm(a) !== "";
}

// ---------------------------------------------------------------------------
// segmentation
// ---------------------------------------------------------------------------

/**
 * A turn begins at each role:"user" message and runs to the next one. The CURRENT turn is
 * anchored on the entry matching plannerContext.userMessage; when Copilot omits it from
 * chatHistory (it often does) the anchor is synthesized after everything else.
 */
export function segment(plannerContext, options = {}) {
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const chat = normalizeChat(plannerContext?.chatHistory, options.gatewayPatterns);
  const tools = normalizeTools(
    plannerContext?.previousToolOutputs || plannerContext?.previousToolsOutputs
  );
  const userMessage = String(plannerContext?.userMessage || "").trim();

  let anchor = null;
  let anchorIsSynthetic = false;
  for (let i = chat.length - 1; i >= 0; i -= 1) {
    if (chat[i].role === "user") {
      if (sameText(chat[i].text, userMessage)) anchor = chat[i];
      break;
    }
  }
  if (!anchor && userMessage) {
    anchor = { kind: "chat", role: "user", text: userMessage, gateway: false, ms: null, ord: chat.length };
    anchorIsSynthetic = true;
  }

  const splitOrd = anchor ? anchor.ord : Number.POSITIVE_INFINITY;
  const priorChat = chat.filter((e) => e.ord < splitOrd);
  const currentChat = chat.filter((e) => e.ord > splitOrd);

  // Prior turns. A leading assistant greeting has no open turn to fold into and is dropped
  // as content — but it is still the chat's start, so it stays available for startedAt.
  const priorTurns = [];
  for (const e of priorChat) {
    if (e.role === "user") {
      priorTurns.push({ index: priorTurns.length + 1, request: e, response: null, tools: [] });
    } else if (priorTurns.length) {
      const t = priorTurns[priorTurns.length - 1];
      t.response = t.response
        ? { ...t.response, text: `${t.response.text}\n${e.text}`, ms: e.ms ?? t.response.ms }
        : { text: e.text, ms: e.ms };
    }
  }

  let anchorMs = anchor ? anchor.ms : null;
  if (anchorMs == null) anchorMs = currentChat.find((e) => e.ms != null)?.ms ?? null;
  if (anchorMs == null && priorTurns.length) {
    const last = priorTurns[priorTurns.length - 1];
    const lastMs = last.response?.ms ?? last.request.ms;
    anchorMs = lastMs != null ? lastMs + 1 : null;
  }
  if (anchorMs == null) anchorMs = nowMs;

  // Bucket tool outputs into turns. A misbucketed output still emits BOTH a conversation
  // entry and a hop, so bucketing errors cost fidelity, never the invariant.
  const bounds = priorTurns.map((t) => t.request.ms).concat([anchorMs]);
  const currentTools = [];
  for (const t of tools) {
    const b = bucketFor(t.ms, bounds);
    if (b == null || b === bounds.length - 1) currentTools.push(t);
    else priorTurns[b].tools.push(t);
  }

  return {
    chat,
    tools,
    priorTurns,
    current: { anchor, anchorIsSynthetic, anchorMs, assistant: currentChat, tools: currentTools }
  };
}

function bucketFor(ms, bounds) {
  if (ms == null) return null;
  let found = null;
  for (let i = 0; i < bounds.length; i += 1) {
    if (bounds[i] != null && ms >= bounds[i] - SKEW_MS) found = i;
  }
  return found;
}

// ---------------------------------------------------------------------------
// the two per-turn collections
// ---------------------------------------------------------------------------

/**
 * context.conversation.messages and context.hops, emitted in lockstep.
 *
 * `resolveToolId(toolName, toolId)` maps a Microsoft tool to its Reva Tool entity id.
 * It must always return a non-empty string — a hop with no resource is worse than a hop
 * with an approximate one, because dropping it would break the count invariant.
 */
export function buildTurnCollections(current, options = {}) {
  const { userId, agentId } = options;
  const resolveToolId = options.resolveToolId || ((name, id) => name || id || "unknown-tool");
  const responseMax = options.responseMaxChars ?? RESPONSE_MAX_CHARS;
  const eventMax = options.eventMax ?? CURRENT_EVENT_MAX;

  // STEP 1 — events. Every filter lives here and nowhere else.
  const events = [];
  if (current.anchor && current.anchor.text.trim()) {
    events.push({ type: "USER", text: current.anchor.text, ms: current.anchorMs, response: "" });
  }
  const orderedTools = current.tools
    .slice()
    .sort((a, b) => (a.ms ?? current.anchorMs ?? 0) - (b.ms ?? current.anchorMs ?? 0) || a.ord - b.ord);
  for (const t of orderedTools) {
    events.push({
      type: "TOOL",
      toolName: t.toolName,
      toolId: t.toolId,
      prompt: hopIntentFromName(t.toolName || t.toolId),
      ms: t.ms,
      // "" is legal and true: asked, not yet answered.
      response: t.text
    });
  }

  // STEP 2 — fold assistant replies into the OPEN event's response. They produce no hop,
  // so they must never become entries of their own.
  for (const a of current.assistant) {
    if (!events.length) continue;
    const open = events[events.length - 1];
    open.response = open.response ? `${open.response}\n${a.text}` : a.text;
  }

  // STEP 3 — monotonic timestamps: forward-fill unknowns, never go backwards.
  let prev = null;
  for (const e of events) {
    const base = e.ms ?? prev ?? current.anchorMs ?? Date.now();
    e.ms = prev == null ? base : Math.max(base, prev);
    prev = e.ms;
  }

  // Keep the user prompt plus the most recent tool events when a turn runs long.
  const kept = events.length > eventMax ? [events[0], ...events.slice(-(eventMax - 1))] : events;

  // STEP 4 — paired emission. The ONLY place either array is written.
  const messages = [];
  const hops = [];
  const emit = (msg, hop) => {
    const seq = messages.length + 1;
    messages.push({ ...msg, seq });
    hops.push({ ...hop, seq });
  };

  for (const e of kept) {
    const time = isoSec(e.ms);
    if (e.type === "USER") {
      emit(
        { role: "user", prompt: e.text, timestamp: time, response: clampChars(e.response, responseMax) },
        {
          subject: { type: "User", id: userId },
          action: "invokeAgent",
          resource: { type: "Agent", id: agentId },
          time
        }
      );
    } else {
      const resourceId = resolveToolId(e.toolName, e.toolId);
      emit(
        {
          role: "tool",
          prompt: e.prompt,
          timestamp: time,
          response: clampChars(e.response, responseMax),
          name: e.toolName || resourceId
        },
        {
          subject: { type: "Agent", id: agentId },
          action: "invokeTool",
          resource: { type: "Tool", id: resourceId },
          time
        }
      );
    }
  }

  return { messages, hops };
}

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------

/**
 * startedAt is when the CHAT began, not this turn. The seed greeting is dropped as content
 * but is exactly the right source for this. Falls back to the oldest tool output, then now.
 */
export function resolveStartedAt(chat, tools, nowMs) {
  const firstChat = chat.find((e) => e.ms != null);
  if (firstChat) return firstChat.ms;
  const toolMs = tools.map((t) => t.ms).filter((m) => m != null);
  if (toolMs.length) return Math.min(...toolMs);
  return nowMs;
}

/**
 * What answered a prior turn: the agent's prose, or failing that the tools it ran.
 *
 * A turn answered by a tool call has no assistant text in chatHistory — the agent "spoke"
 * by invoking something. Reporting that turn as unanswered throws away the setup half of
 * every drift pair whose first move was a lookup, which is most of them.
 *
 * The tool NAME is included, not just its output, because "asked for a risk score, ran
 * Fetch-Risk-Score" is a different fact from "asked for a risk score, received 72" — the
 * evaluator is judging a trajectory of actions, so the action belongs in it.
 *
 * Returns null only when the turn really has nothing: no prose, no tool result.
 */
function resolveTurnResponse(t) {
  const prose = String(t.response?.text ?? "").trim();
  if (prose !== "") return { text: t.response.text, ms: t.response.ms };

  const ran = (t.tools || []).filter((tool) => String(tool.text ?? "").trim() !== "");
  if (ran.length === 0) return null;

  const text = ran.map((tool) => (tool.toolName ? `${tool.toolName} → ${tool.text}` : tool.text)).join("\n");
  // The latest tool wins the timestamp: it is when the turn actually finished.
  const ms = ran.reduce((latest, tool) => (tool.ms != null && (latest == null || tool.ms > latest) ? tool.ms : latest), null);
  return { text, ms };
}

function side(role, text, ms, maxChars) {
  return {
    role,
    contentType: "text/plain",
    content: clampChars(text, maxChars),
    timestamp: isoSec(ms)
  };
}

/**
 * The turns BEFORE this one. Two PDP rules are refused on the entry hop, which presents to
 * a user as not being authorized at all:
 *   - session.turn must be >= 2 when session.messages is present
 *   - session.messages[0].request.timestamp must not precede session.startedAt
 * Both hold by construction here: turn is derived from the same history, and startedAt is
 * clamped against the first kept request below.
 */
export function buildSessionBlock(priorTurns, options = {}) {
  const maxTurns = options.maxTurns ?? SESSION_MAX_TURNS;
  const maxChars = options.maxChars ?? SESSION_MAX_CHARS;
  const block = { id: options.sessionId, turn: priorTurns.length + 1 };

  let startedAtMs = options.startedAtMs;

  // A turn whose answer was never captured is not a completed turn, and the PDP refuses the
  // WHOLE request over it. Verified against pr06 on 2026-09-10:
  //   response key absent  -> 400 invalid session: session.messages[0].response is required
  //   response.content ""  -> 400 invalid session: session.messages[0].response.content is required
  //
  // Copilot produces one routinely, and the production payload of 2026-08-27 is exactly it:
  // the user asks for a risk score, the agent answers by CALLING A TOOL, and chatHistory
  // carries no assistant text at all for that turn. Dropping it kept the call working but
  // emptied session.messages — so on the one conversation the drift demo is built around,
  // the evaluator saw the export request with no trace of the narrow lookup it escalated
  // from. The trajectory that defect #4 restored was missing again, by a different route.
  //
  // But that turn was answered; the answer is just a tool result rather than prose, and it
  // is already sitting on t.tools where segment() bucketed it. Using it is not fabricating a
  // response — it is the actual output the agent produced, which is the same thing the Kong
  // plugin captures in its log phase. So: prose if we have it, otherwise the tool result,
  // and only failing that is a turn genuinely unanswerable and dropped.
  const resolved = priorTurns.map((t) => ({ turn: t, response: resolveTurnResponse(t) }));
  const answered = resolved.filter((r) => r.response !== null);

  // Oldest dropped first — recency is what a trajectory judgement needs.
  const kept = answered.slice(-maxTurns);
  const messages = [];
  let carriedMs = startedAtMs;
  for (const { turn: t, response } of kept) {
    const reqMs = t.request.ms ?? carriedMs;
    carriedMs = reqMs;
    // An answer cannot predate its question, and the PDP enforces that literally:
    //   400 invalid session: session.messages[N].response.timestamp
    //       must not precede its request.timestamp
    // (verified against pr06, 2026-09-10). Copilot stamps the two messages independently, so
    // clock skew of a few milliseconds between them is enough to fail the WHOLE request —
    // the same conversation-wide wedge as an unanswered turn, from a different direction.
    // Clamping costs a meaningless sub-second reordering; not clamping costs the call.
    const respMs = Math.max(response.ms ?? reqMs, reqMs);
    carriedMs = respMs;
    // `turn` stays ABSOLUTE: with 25 prior turns, messages numbered 1..10 beside
    // session.turn 26 reads as a contradiction; 16..25 reads as a window. Dropping an
    // unanswered turn therefore leaves a GAP rather than renumbering — the turn happened,
    // we just cannot describe it. pr06 accepts gapped and mid-chat windows (probed).
    messages.push({
      turn: t.index,
      request: side("user", t.request.text, reqMs, maxChars),
      response: side("agent", response.text, respMs, maxChars)
    });
  }

  if (messages.length) {
    const firstMs = parseTs(messages[0].request.timestamp);
    if (firstMs != null && firstMs < startedAtMs) startedAtMs = firstMs;
  }
  block.startedAt = isoSec(startedAtMs);

  // Omit the key entirely when there is no history — the contract's turn-1 payloads have
  // no `messages` key at all, and whether [] counts as "present" is untested.
  if (messages.length) block.messages = messages;
  return block;
}

// ---------------------------------------------------------------------------
// size
// ---------------------------------------------------------------------------

export const HARD_BODY_LIMIT = 1048576;
export const SAFE_BODY_LIMIT = 900000;

function bodyBytes(body) {
  try {
    return Buffer.byteLength(JSON.stringify(body), "utf8");
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

/**
 * The PDP rejects a body over 1 MiB BEFORE authorization, so an unbounded chat would turn
 * every hop into a hard failure — gradually, as the conversation grows, which is the worst
 * way to find a limit. Trim in increasing order of damage and never fail closed on size.
 * Rung 5 drops conversation/hops IN PAIRS and re-seqs, or it would reintroduce divergence.
 */
export function fitToBudget(body, limit = SAFE_BODY_LIMIT) {
  const steps = [];
  if (bodyBytes(body) <= limit) return { body, trimSteps: steps };

  const ctx = body.context || {};
  const msgs = () => ctx.conversation?.messages || [];

  // 1. tool arguments — bulk is redundant with transmission.content
  if (body.inputValues && typeof body.inputValues === "object") {
    for (const [k, v] of Object.entries(body.inputValues)) {
      if (typeof v === "string" && v.length > 2000) body.inputValues[k] = clampChars(v, 2000);
    }
    steps.push("inputValues:2000");
    if (bodyBytes(body) <= limit) return { body, trimSteps: steps };
  }

  // 2. current-turn responses
  for (const cap of [2000, 1000, 500, 200]) {
    for (const m of msgs()) m.response = clampChars(m.response, cap);
    steps.push(`conversation.response:${cap}`);
    if (bodyBytes(body) <= limit) return { body, trimSteps: steps };
  }

  // 3. session per-side cap
  for (const cap of [1000, 500, 200]) {
    for (const t of body.session?.messages || []) {
      if (t.request) t.request.content = clampChars(t.request.content, cap);
      if (t.response) t.response.content = clampChars(t.response.content, cap);
    }
    steps.push(`session.content:${cap}`);
    if (bodyBytes(body) <= limit) return { body, trimSteps: steps };
  }

  // 4. session turn count, oldest first
  for (const keep of [6, 4, 2, 1]) {
    if (body.session?.messages?.length > keep) {
      body.session.messages = body.session.messages.slice(-keep);
      steps.push(`session.turns:${keep}`);
      if (bodyBytes(body) <= limit) return { body, trimSteps: steps };
    }
  }

  // 5. structural loss — the journey is now abridged. Drop in pairs, keep event 0.
  while (msgs().length > 1 && bodyBytes(body) > limit) {
    ctx.conversation.messages.splice(1, 1);
    ctx.hops.splice(1, 1);
    ctx.conversation.messages.forEach((m, i) => {
      m.seq = i + 1;
    });
    ctx.hops.forEach((h, i) => {
      h.seq = i + 1;
    });
    steps.push("events:paired-drop");
  }
  if (bodyBytes(body) <= limit) return { body, trimSteps: steps };

  // 6. drop history entirely (turn >= 2 with no messages violates no rule)
  if (body.session?.messages) {
    delete body.session.messages;
    steps.push("session.messages:dropped");
    if (bodyBytes(body) <= limit) return { body, trimSteps: steps };
  }

  // 7. minimal valid body
  body.context = {};
  steps.push("context:emptied");
  return { body, trimSteps: steps };
}
