/**
 * Strip personal and conversational content from a Copilot webhook payload before it is
 * written to the observability store.
 *
 * WHY THIS IS THE DEFAULT
 *
 * The stored payload is the richest thing this service touches: the user's own words, the
 * planner's reasoning about them, whatever the tools returned, the arguments of the call,
 * the user's Entra object id and their IP address. It is retained in DynamoDB and served
 * back over HTTP. Any deployment that fails to lock those routes down publishes a
 * transcript of its users' conversations — and the routes are HTTP GETs, so "fails to lock
 * down" means "forgot one line of gateway config".
 *
 * None of that content is needed to answer the questions the event log exists for: was the
 * call allowed, which tool, which agent, which user, how long did the PDP take, did the
 * payload shape come out right. Those are ids, names, counts and timings, all of which
 * survive redaction untouched.
 *
 * So the content is dropped unless an operator asks for it. OBS_STORE_PROMPTS=true turns it
 * back on for a debugging session; the setting exists because reproducing a payload problem
 * without the payload is genuinely hard, and because pretending otherwise would just push
 * people to disable the whole event log.
 *
 * Redaction happens on the way IN, not on the way out. Data that was never written cannot
 * leak from a route someone forgot to protect, cannot be read by whoever has database
 * access, and does not sit in a backup.
 */

export const REDACTED = "[redacted]";

/** True when the operator has explicitly opted into storing conversation content. */
export function storePromptsEnabled(env = process.env) {
  return env.OBS_STORE_PROMPTS === "true" || env.OBS_STORE_PROMPTS === "1";
}

/** Replace a string with the marker, preserving its length as a rough diagnostic aid. */
function mark(value) {
  if (typeof value !== "string" || value === "") return value;
  return `${REDACTED} (${value.length} chars)`;
}

/**
 * A shallow-cloned payload with free text removed. Structure, names, ids, types, counts and
 * timestamps are all kept, because that is what a diagnosis is made of.
 */
export function redactAnalyzePayload(payload) {
  if (!payload || typeof payload !== "object") return payload;

  const out = { ...payload };

  const meta = payload.conversationMetadata;
  if (meta && typeof meta === "object") {
    // The client IP is personal data and is never needed to debug a decision. The rest of
    // conversationMetadata is ids and flags, which are.
    out.conversationMetadata = { ...meta };
    if (meta.incomingClientIp) out.conversationMetadata.incomingClientIp = REDACTED;
  }

  const pc = payload.plannerContext;
  if (pc && typeof pc === "object") {
    const nextPc = { ...pc };
    if (typeof pc.userMessage === "string") nextPc.userMessage = mark(pc.userMessage);
    // The planner's own reasoning quotes the user freely, so it is content too.
    if (typeof pc.thought === "string") nextPc.thought = mark(pc.thought);

    if (Array.isArray(pc.chatHistory)) {
      nextPc.chatHistory = pc.chatHistory.map((m) =>
        m && typeof m === "object" ? { ...m, content: mark(typeof m.content === "string" ? m.content : "") } : m
      );
    }

    // Tool results are where injected instructions arrive, so they are exactly the thing an
    // operator will want during an incident — and exactly the thing not to retain by default.
    for (const key of ["previousToolOutputs", "previousToolsOutputs"]) {
      if (!Array.isArray(pc[key])) continue;
      nextPc[key] = pc[key].map((t) => {
        if (!t || typeof t !== "object") return t;
        const next = { ...t };
        if (Array.isArray(t.outputs)) {
          next.outputs = t.outputs.map((o) =>
            o && typeof o === "object" ? { ...o, value: REDACTED } : o
          );
        } else if (t.outputs !== undefined) {
          next.outputs = REDACTED;
        }
        return next;
      });
    }
    out.plannerContext = nextPc;
  }

  // Argument NAMES are a useful signal and are declared in toolDefinition anyway; the values
  // are user data — a recipient address, an export path, a message body.
  if (payload.inputValues && typeof payload.inputValues === "object" && !Array.isArray(payload.inputValues)) {
    out.inputValues = Object.fromEntries(Object.keys(payload.inputValues).map((k) => [k, REDACTED]));
  }
  if (Array.isArray(payload.inputParameters)) {
    out.inputParameters = payload.inputParameters.map((p) =>
      p && typeof p === "object" ? { ...p, value: REDACTED } : p
    );
  }

  // toolDefinition is a schema, not user data: names, descriptions and types authored by
  // whoever built the tool. Kept whole — it is often the thing that explains a decision.
  return out;
}

/** Redact unless the operator opted in. The one place callers should need. */
export function redactForStorage(payload, env = process.env) {
  return storePromptsEnabled(env) ? payload : redactAnalyzePayload(payload);
}
