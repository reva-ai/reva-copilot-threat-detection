/**
 * transmission.content for an agent -> tool hop.
 *
 * The PDP's drift evaluator compares WHAT THIS HOP DOES against what was asked. The "what
 * was asked" lives in context.conversation and session.messages; the "what this hop does"
 * is transmission.content. Sending the user's own prompt here makes the payload agree with
 * itself and the verdict is ALIGNED however far the agent has wandered — the hop is being
 * compared against itself.
 *
 * This ships to clients with tools we have never seen, so there is no per-tool phrasing
 * table. The sentence is assembled from the tool NAME (verb phrase) and the SHAPE of the
 * parameter names (prepositional phrases), which generalises.
 */

/** Verbs that read naturally as the head of a sentence; anything else gets "Invoke ...". */
const VERBS = new Set([
  "get", "list", "send", "create", "update", "delete", "post", "put", "patch", "search",
  "find", "lookup", "fetch", "read", "write", "export", "import", "upload", "download",
  "run", "execute", "submit", "approve", "reject", "transfer", "pay", "notify", "email",
  "add", "remove", "set", "cancel", "schedule", "share", "grant", "revoke", "sync",
  "generate", "query", "retrieve", "archive", "publish", "invoke", "call", "check",
  "validate", "convert", "start", "stop", "open", "close", "block"
]);

/**
 * Parameter-NAME shape -> phrase. Matching on the name rather than the tool means a client's
 * unknown "Dispatch-Courier" tool with a `to` parameter still reads "... to <value>".
 * Phrases beginning "with " are grouped into a single trailing clause.
 */
const SHAPES = [
  [/^(to|recipient|recipients|toaddress|to_address|dest|destination|target|assignee)$/i, (v) => `to ${v}`],
  [/^(from|sender|source|src|origin|fromaddress|from_address)$/i, (v) => `from ${v}`],
  [/^(subject|title|headline)$/i, (v) => `with subject '${v}'`],
  [/^(body|message|content|text|note|comment|description)$/i, (v) => `with body '${v}'`],
  [/^(query|q|search|searchterm|search_term|filter|keyword)$/i, (v) => `for '${v}'`],
  [/^(path|url|uri|file|filename|folder|location|endpoint)$/i, (v) => `at ${v}`],
  // Matched against the HUMANIZED name so camelCase ("accountId" -> "account id") is caught
  // as well as snake/kebab ("policy_id"). Bare "id" leaves no noun, so it renders "for <v>".
  [
    /(^|\s)(id|ids|key|ref|number|no)$/i,
    (v, n) => {
      const noun = humanize(stripIdSuffix(n)).trim();
      return noun ? `for ${noun} ${v}` : `for ${v}`;
    }
  ],
  [/^(amount|value|total|qty|quantity|count|limit|price)$/i, (v, n) => `${humanize(n)} ${v}`]
];

const MAX_ARGS = 4;
const MAX_VALUE_CHARS = 120;
const MAX_SENTENCE_CHARS = 600;
const MAX_THOUGHT_CHARS = 300;

/** Control characters, as an escaped class — never write these literally in source. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f]+/g;

function clamp(s, n) {
  const str = String(s == null ? "" : s);
  return str.length > n ? `${str.slice(0, n)}…` : str;
}

function cap(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function stripIdSuffix(name) {
  return String(name || "").replace(/([_\-])?(id|ids|key|ref|number|no)$/i, "");
}

function humanize(name) {
  return String(name || "")
    .replace(/[_\-.]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function safeJson(v) {
  try {
    return JSON.stringify(v);
  } catch {
    return "";
  }
}

function hasValue(v) {
  if (v == null) return false;
  if (typeof v === "string") return v.trim() !== "";
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

/**
 * Collapse control characters and newlines so an argument cannot visually reframe the
 * sentence. Deliberately NOT semantic sanitisation — if an argument carries an injected
 * instruction, that is precisely what the PDP is being asked to score.
 */
export function formatValue(v) {
  if (v == null) return "";
  if (typeof v === "boolean" || typeof v === "number") return String(v);
  if (Array.isArray(v)) {
    const head = v.slice(0, 3).map(formatValue).filter(Boolean).join(", ");
    return v.length > 3 ? `${head}, …` : head;
  }
  if (typeof v === "object") return clamp(safeJson(v), MAX_VALUE_CHARS);
  return clamp(String(v).replace(CONTROL_CHARS, " ").replace(/\s+/g, " ").trim(), MAX_VALUE_CHARS);
}

/** "pub_Foo.action.Send-Notification-Email" -> ["send","notification","email"] */
export function toolNameTokens(rawName) {
  const raw = String(rawName || "");
  const base = raw.split(".").pop().split("/").pop();
  return base
    .replace(/[_\-.]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .split(" ")
    .filter(Boolean);
}

/**
 * One sentence describing the tool call being authorized.
 * `options.thought` appends the planner's own rationale AFTER the deterministic sentence,
 * so the judged string stays grounded in the actual arguments even when the thought is
 * empty, vague, or itself the product of a poisoned tool output.
 */
export function hopIntent(toolDefinition, inputValues, options = {}) {
  const tokens = toolNameTokens(toolDefinition?.name || toolDefinition?.id || "");

  let phrase;
  if (!tokens.length) phrase = "Invoke an unnamed tool";
  else if (VERBS.has(tokens[0])) phrase = cap(tokens.join(" "));
  else phrase = `Invoke ${tokens.join(" ")}`;

  const values =
    inputValues && typeof inputValues === "object" && !Array.isArray(inputValues) ? inputValues : {};
  // Declared parameter order first — it is the tool author's own reading order.
  const declared = Array.isArray(toolDefinition?.inputParameters)
    ? toolDefinition.inputParameters.map((p) => p?.name).filter((n) => typeof n === "string")
    : [];
  const keys = [...new Set([...declared, ...Object.keys(values)])].filter((k) => hasValue(values[k]));

  let sentence = phrase;
  if (keys.length) {
    const lead = [];
    const trailing = [];
    for (const k of keys.slice(0, MAX_ARGS)) {
      const v = formatValue(values[k]);
      if (!v) continue;
      const shape = SHAPES.find(([re]) => re.test(k) || re.test(humanize(k)));
      const rendered = shape ? shape[1](v, k) : `${humanize(k)} ${v}`;
      if (rendered.startsWith("with ")) trailing.push(rendered.slice(5));
      else lead.push(rendered);
    }
    if (lead.length) sentence += ` ${lead.join(" ")}`;
    if (trailing.length) sentence += ` with ${trailing.join(", ")}`;
    const omitted = keys.length - Math.min(keys.length, MAX_ARGS);
    if (omitted > 0) sentence += ` and ${omitted} more parameter${omitted > 1 ? "s" : ""}`;
  }

  sentence = `${clamp(sentence.replace(/\s+/g, " ").trim(), MAX_SENTENCE_CHARS)}.`;

  const thought = typeof options.thought === "string" ? options.thought.trim() : "";
  if (thought && options.includeThought) {
    sentence += ` Planner rationale: ${clamp(thought, MAX_THOUGHT_CHARS)}`;
  }
  return sentence;
}

/** Verb phrase only — used for PAST tool exchanges, where Microsoft gives us no arguments. */
export function hopIntentFromName(toolName) {
  return hopIntent({ name: toolName }, null);
}
