import test from "node:test";
import assert from "node:assert/strict";
import {
  GATEWAY_MARKER,
  buildSessionBlock,
  buildTurnCollections,
  fitToBudget,
  isoSec,
  normalizeChat,
  parseTs,
  resolveStartedAt,
  segment,
  serializeToolOutputs
} from "../src/core/turn.mjs";

const NOW = Date.parse("2026-06-20T09:00:00Z");
const opts = { userId: "alice", agentId: "underwriter-copilot" };

function chat(role, content, timestamp) {
  return { id: Math.random().toString(36).slice(2), role, content, timestamp };
}
function toolOut(toolName, timestamp, outputs = [{ name: "ok", value: true }]) {
  return { toolName, toolId: `id.${toolName}`, timestamp, outputs };
}

// --- timestamps -------------------------------------------------------------

test("parseTs returns null (not 0) for unparseable input", () => {
  // 0 would sort a bad timestamp to the front of the chronology and silently reorder
  // the journey the drift evaluator reads. This was the v1 bug.
  assert.equal(parseTs("not-a-date"), null);
  assert.equal(parseTs(""), null);
  assert.equal(parseTs(undefined), null);
  assert.equal(parseTs(null), null);
});

test("parseTs handles .NET 7-digit fractional seconds and offsets", () => {
  assert.equal(parseTs("2026-06-20T08:03:49.9651390+00:00"), Date.parse("2026-06-20T08:03:49.965Z"));
  assert.equal(parseTs("2026-06-20T08:00:00+05:30"), Date.parse("2026-06-20T02:30:00Z"));
});

test("parseTs handles epoch seconds and millis", () => {
  assert.equal(parseTs(1781942637), 1781942637000);
  assert.equal(parseTs(1781942637433), 1781942637433);
});

test("isoSec emits second precision", () => {
  assert.equal(isoSec(Date.parse("2026-06-20T08:03:49.965Z")), "2026-06-20T08:03:49Z");
});

// --- normalisation ----------------------------------------------------------

test("normalizeChat reverses newest-first into chronological order", () => {
  const out = normalizeChat([
    chat("user", "second", "2026-06-20T08:01:00Z"),
    chat("user", "first", "2026-06-20T08:00:00Z")
  ]);
  assert.deepEqual(out.map((e) => e.text), ["first", "second"]);
});

test("normalizeChat replaces our own gateway block messages", () => {
  const out = normalizeChat([
    chat("assistant", 'Request Blocked - Reva Trust Gateway. Matched term: "confidential claims"', "2026-06-20T08:00:00Z")
  ]);
  assert.equal(out[0].text, GATEWAY_MARKER);
  assert.equal(out[0].gateway, true);
  // The blocked term must not survive: keeping it re-injects it into every later payload
  // and a term policy then fires on our own enforcement text.
  assert.ok(!out[0].text.includes("confidential claims"));
});

test("normalizeChat drops system turns and coerces non-string content", () => {
  const out = normalizeChat([
    chat("system", "you are a bot", "2026-06-20T08:00:00Z"),
    chat("user", { card: "adaptive" }, "2026-06-20T08:00:01Z")
  ]);
  assert.equal(out.length, 1);
  assert.equal(out[0].text, '{"card":"adaptive"}');
});

test("serializeToolOutputs flattens Microsoft's [{name,value}] shape", () => {
  assert.equal(serializeToolOutputs([{ name: "a", value: 1 }, { name: "b", value: "x" }]), '{"a":1,"b":"x"}');
  assert.equal(serializeToolOutputs([]), "");
  assert.equal(serializeToolOutputs(null), "");
});

// --- the count invariant ----------------------------------------------------

function counts(plannerContext) {
  const seg = segment(plannerContext, { nowMs: NOW });
  const { messages, hops } = buildTurnCollections(seg.current, opts);
  return { messages, hops, seg };
}

test("INVARIANT: conversation and hops are equal for every input shape", () => {
  const cases = [
    { userMessage: "hi", chatHistory: [], previousToolOutputs: [] },
    { userMessage: "", chatHistory: [], previousToolOutputs: [] },
    { userMessage: "hi", chatHistory: [chat("user", "hi", "2026-06-20T08:00:00Z")], previousToolOutputs: [] },
    // tool output with NO toolName — v1 emitted the message but skipped the hop
    { userMessage: "hi", chatHistory: [], previousToolOutputs: [{ timestamp: "2026-06-20T08:00:00Z", outputs: [{ name: "a", value: 1 }] }] },
    // tool output that serialises to "" — v1 dropped both, losing a real hop
    { userMessage: "hi", chatHistory: [], previousToolOutputs: [toolOut("T", "2026-06-20T08:00:00Z", [])] },
    // unparseable timestamps everywhere
    { userMessage: "hi", chatHistory: [chat("user", "hi", "nope")], previousToolOutputs: [toolOut("T", "nope")] },
    // assistant replies mid-turn
    { userMessage: "hi", chatHistory: [chat("assistant", "thinking", "2026-06-20T08:00:05Z"), chat("user", "hi", "2026-06-20T08:00:00Z")], previousToolOutputs: [] },
    // many tools
    { userMessage: "hi", chatHistory: [], previousToolOutputs: Array.from({ length: 40 }, (_, i) => toolOut(`T${i}`, `2026-06-20T08:${String(i).padStart(2, "0")}:00Z`)) },
    { userMessage: undefined, chatHistory: undefined, previousToolOutputs: undefined }
  ];
  for (const [i, pc] of cases.entries()) {
    const { messages, hops } = counts(pc);
    assert.equal(messages.length, hops.length, `case ${i}: ${messages.length} vs ${hops.length}`);
    for (let k = 0; k < messages.length; k += 1) {
      assert.equal(messages[k].seq, k + 1, `case ${i}: message seq`);
      assert.equal(hops[k].seq, k + 1, `case ${i}: hop seq`);
      assert.equal(messages[k].timestamp, hops[k].time, `case ${i}: paired timestamps`);
    }
  }
});

test("a tool output with no toolName still produces a hop", () => {
  const { messages, hops } = counts({
    userMessage: "hi",
    chatHistory: [],
    previousToolOutputs: [{ timestamp: "2026-06-20T08:00:00Z", outputs: [{ name: "a", value: 1 }] }]
  });
  assert.equal(messages.length, 2);
  assert.equal(hops.length, 2);
  assert.equal(hops[1].resource.id, "unknown-tool");
});

test("assistant replies fold into the previous exchange's response, not their own entry", () => {
  const { messages, hops } = counts({
    userMessage: "hi",
    chatHistory: [chat("assistant", "one moment", "2026-06-20T08:00:05Z"), chat("user", "hi", "2026-06-20T08:00:00Z")],
    previousToolOutputs: []
  });
  assert.equal(messages.length, 1);
  assert.equal(hops.length, 1);
  assert.equal(messages[0].response, "one moment");
});

test("empty turn yields zero entries so context can be sent as {}", () => {
  const { messages, hops } = counts({ userMessage: "", chatHistory: [], previousToolOutputs: [] });
  assert.equal(messages.length, 0);
  assert.equal(hops.length, 0);
});

test("hops carry a bare action string and subject (not source)", () => {
  const { hops } = counts({ userMessage: "hi", chatHistory: [], previousToolOutputs: [toolOut("T", "2026-06-20T08:01:00Z")] });
  assert.equal(typeof hops[0].action, "string");
  assert.equal(hops[0].action, "invokeAgent");
  assert.equal(hops[1].action, "invokeTool");
  assert.ok(hops[0].subject);
  assert.equal(hops[0].source, undefined);
});

test("timestamps are clamped monotonic across the turn", () => {
  const { messages } = counts({
    userMessage: "hi",
    chatHistory: [chat("user", "hi", "2026-06-20T08:05:00Z")],
    previousToolOutputs: [toolOut("Late", "2026-06-20T08:00:00Z")]
  });
  const times = messages.map((m) => Date.parse(m.timestamp));
  for (let i = 1; i < times.length; i += 1) assert.ok(times[i] >= times[i - 1], "non-decreasing");
});

// --- segmentation -----------------------------------------------------------

test("segment splits prior turns from the current turn on user messages", () => {
  const seg = segment({
    userMessage: "third",
    chatHistory: [
      chat("assistant", "b2", "2026-06-20T08:02:10Z"),
      chat("user", "second", "2026-06-20T08:02:00Z"),
      chat("assistant", "b1", "2026-06-20T08:01:10Z"),
      chat("user", "first", "2026-06-20T08:01:00Z"),
      chat("assistant", "greeting", "2026-06-20T08:00:00Z")
    ],
    previousToolOutputs: []
  }, { nowMs: NOW });
  assert.equal(seg.priorTurns.length, 2);
  assert.equal(seg.priorTurns[0].request.text, "first");
  assert.equal(seg.priorTurns[0].response.text, "b1");
  assert.equal(seg.current.anchorIsSynthetic, true);
});

test("segment reuses the chat entry when userMessage is already in history", () => {
  const seg = segment({
    userMessage: "hello there",
    chatHistory: [chat("user", "hello there", "2026-06-20T08:00:00Z")],
    previousToolOutputs: []
  }, { nowMs: NOW });
  assert.equal(seg.current.anchorIsSynthetic, false);
  assert.equal(seg.current.anchorMs, Date.parse("2026-06-20T08:00:00Z"));
  assert.equal(seg.priorTurns.length, 0);
});

test("tool outputs are bucketed into the turn they belong to", () => {
  const seg = segment({
    userMessage: "now",
    chatHistory: [
      chat("assistant", "here you go", "2026-06-20T08:00:10Z"),
      chat("user", "earlier", "2026-06-20T08:00:00Z")
    ],
    // Old ran while the prior turn was still open; New long after it closed.
    previousToolOutputs: [toolOut("Old", "2026-06-20T08:00:05Z"), toolOut("New", "2026-06-20T09:00:30Z")]
  }, { nowMs: NOW });
  assert.equal(seg.priorTurns.length, 1);
  assert.deepEqual(seg.priorTurns[0].tools.map((t) => t.toolName), ["Old"]);
  assert.deepEqual(seg.current.tools.map((t) => t.toolName), ["New"]);
});

test("an ambiguously-timed tool output is credited to the CURRENT turn", () => {
  // Copilot often omits the current user message from chatHistory, so the boundary between
  // the last prior turn and this one is only approximately known. The two errors are not
  // symmetric: a tool wrongly placed in the current turn is noise in conversation/hops,
  // while one wrongly placed in a PRIOR turn disappears entirely — session.messages is a
  // user/agent request-response pair with no slot for tool traffic. So ambiguity resolves
  // toward the current turn, where it stays visible.
  const seg = segment({
    userMessage: "now",
    chatHistory: [chat("user", "earlier", "2026-06-20T08:00:00Z")],
    previousToolOutputs: [toolOut("Ambiguous", "2026-06-20T08:00:30Z")]
  }, { nowMs: NOW });
  assert.deepEqual(seg.current.tools.map((t) => t.toolName), ["Ambiguous"]);
  assert.equal(seg.priorTurns[0].tools.length, 0);
});

// --- session ----------------------------------------------------------------

test("session omits messages entirely on turn 1", () => {
  const block = buildSessionBlock([], { sessionId: "s", startedAtMs: NOW });
  assert.equal(block.turn, 1);
  assert.equal("messages" in block, false);
});

test("session.turn is >= 2 whenever messages are present", () => {
  const seg = segment({
    userMessage: "b",
    // newest-first, and the turn must be ANSWERED or it is dropped as incomplete
    chatHistory: [chat("assistant", "a-reply", "2026-06-20T08:00:30Z"), chat("user", "a", "2026-06-20T08:00:00Z")],
    previousToolOutputs: []
  }, { nowMs: NOW });
  const block = buildSessionBlock(seg.priorTurns, { sessionId: "s", startedAtMs: Date.parse("2026-06-20T08:00:00Z") });
  assert.ok(block.messages.length >= 1);
  assert.ok(block.turn >= 2);
});

test("session.startedAt never postdates messages[0].request.timestamp", () => {
  const seg = segment({
    userMessage: "b",
    chatHistory: [chat("assistant", "a-reply", "2026-06-20T08:00:30Z"), chat("user", "a", "2026-06-20T08:00:00Z")],
    previousToolOutputs: []
  }, { nowMs: NOW });
  // Deliberately pass a startedAt LATER than the history, the mistake the contract warns about.
  const block = buildSessionBlock(seg.priorTurns, { sessionId: "s", startedAtMs: Date.parse("2026-06-20T23:00:00Z") });
  assert.ok(Date.parse(block.startedAt) <= Date.parse(block.messages[0].request.timestamp));
});

test("session keeps the newest turns and numbers them absolutely", () => {
  const prior = Array.from({ length: 25 }, (_, i) => ({
    index: i + 1,
    request: { text: `q${i + 1}`, ms: NOW + i * 1000 },
    response: { text: `a${i + 1}`, ms: NOW + i * 1000 + 500 },
    tools: []
  }));
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW, maxTurns: 10 });
  assert.equal(block.messages.length, 10);
  assert.equal(block.turn, 26);
  // Window 16..25 reads as a window; 1..10 beside turn 26 would read as a contradiction.
  assert.equal(block.messages[0].turn, 16);
  assert.equal(block.messages[9].turn, 25);
});

test("session truncates long sides with a marker", () => {
  const prior = [{
    index: 1,
    request: { text: "x".repeat(5000), ms: NOW },
    response: { text: "y".repeat(5000), ms: NOW + 500 },
    tools: []
  }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW, maxChars: 2000 });
  assert.ok(block.messages[0].request.content.endsWith("[truncated]"));
  assert.ok(block.messages[0].response.content.endsWith("[truncated]"));
});

// The PDP refuses the whole request over an incomplete prior turn. Verified against pr06
// on 2026-09-10: a missing `response` key answers 400 "session.messages[0].response is
// required", and response.content "" answers 400 "...response.content is required". Both
// carry decision:false, so an unfiltered turn reads downstream as a policy deny.
test("session drops a prior turn whose answer was never captured", () => {
  const prior = [
    { index: 1, request: { text: "summarise policy P-1", ms: NOW }, response: null, tools: [] },
    { index: 2, request: { text: "now email it out", ms: NOW + 1000 },
      response: { text: "done", ms: NOW + 1500 }, tools: [] }
  ];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW });
  assert.equal(block.messages.length, 1);
  assert.equal(block.messages[0].turn, 2);
  // The dropped turn still happened, so the CURRENT turn number does not shift down.
  assert.equal(block.turn, 3);
  for (const m of block.messages) assert.ok(m.response && m.response.content !== "");
});

// A turn answered by a TOOL CALL has no assistant prose. Copilot does this constantly, and
// the 2026-08-27 production payload is exactly it: reporting such a turn as unanswered
// emptied session.messages on the one conversation the drift demo is built around.
test("a turn answered by a tool call is kept, using the tool result", () => {
  const prior = [{
    index: 1,
    request: { text: "What's the risk score for P-10234?", ms: NOW },
    response: null,
    tools: [{ toolName: "Fetch-Risk-Score", text: '{"riskScore":72}', ms: NOW + 2000, ord: 0 }]
  }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW - 1000 });
  assert.equal(block.messages.length, 1);
  // The tool NAME is part of it: "ran Fetch-Risk-Score" is a different fact from "got 72",
  // and a trajectory judgement is about the actions.
  assert.equal(block.messages[0].response.content, 'Fetch-Risk-Score → {"riskScore":72}');
  // The turn finished when the tool answered, not when it was asked.
  assert.equal(block.messages[0].response.timestamp, isoSec(NOW + 2000));
});

test("assistant prose wins over the tool result when both exist", () => {
  const prior = [{
    index: 1,
    request: { text: "q", ms: NOW },
    response: { text: "The risk score is 72 (MEDIUM).", ms: NOW + 3000 },
    tools: [{ toolName: "Fetch-Risk-Score", text: '{"riskScore":72}', ms: NOW + 2000, ord: 0 }]
  }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW });
  assert.equal(block.messages[0].response.content, "The risk score is 72 (MEDIUM).");
});

test("several tools on one turn are all reported", () => {
  const prior = [{
    index: 1,
    request: { text: "q", ms: NOW },
    response: null,
    tools: [
      { toolName: "Fetch-Risk-Score", text: '{"riskScore":72}', ms: NOW + 1000, ord: 0 },
      { toolName: "Search-Policy-Database", text: '{"hits":4}', ms: NOW + 2000, ord: 1 }
    ]
  }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW });
  assert.match(block.messages[0].response.content, /Fetch-Risk-Score/);
  assert.match(block.messages[0].response.content, /Search-Policy-Database/);
});

test("a turn with neither prose nor a tool result is still dropped", () => {
  // The fallback widens what counts as answered; it does not make everything answerable.
  const prior = [
    { index: 1, request: { text: "q1", ms: NOW }, response: null, tools: [] },
    { index: 2, request: { text: "q2", ms: NOW + 1000 }, response: null, tools: [{ toolName: "T", text: "", ms: NOW }] }
  ];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW });
  assert.equal(block.messages, undefined);
  assert.equal(block.turn, 3);
});

test("a tool-derived response still cannot predate its request", () => {
  const prior = [{
    index: 1,
    request: { text: "q", ms: NOW },
    response: null,
    tools: [{ toolName: "T", text: "{}", ms: NOW - 9000, ord: 0 }] // skewed clock
  }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW - 10000 });
  const m = block.messages[0];
  assert.ok(Date.parse(m.response.timestamp) >= Date.parse(m.request.timestamp));
});

test("a response is never timestamped before its own request", () => {
  // pr06, 2026-09-10:
  //   400 invalid session: session.messages[0].response.timestamp
  //       must not precede its request.timestamp
  // Copilot stamps the two messages independently, so a few milliseconds of clock skew
  // between them fails the WHOLE request — the same conversation-wide wedge as an
  // unanswered turn, arriving from the other direction.
  const prior = [{
    index: 1,
    request: { text: "q", ms: NOW },
    response: { text: "a", ms: NOW - 5000 }, // answered 5s before it was asked
    tools: []
  }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW - 10000 });
  const req = Date.parse(block.messages[0].request.timestamp);
  const res = Date.parse(block.messages[0].response.timestamp);
  assert.ok(res >= req, `response ${res} must not precede request ${req}`);
});

test("session drops a prior turn whose answer is whitespace only", () => {
  const prior = [{ index: 1, request: { text: "q", ms: NOW }, response: { text: "   ", ms: NOW + 1 }, tools: [] }];
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW });
  // No usable history left, so the key is omitted entirely rather than sent empty —
  // pr06 accepts turn >= 2 with no messages key (probed).
  assert.equal(block.messages, undefined);
  assert.equal(block.turn, 2);
});

test("the session window is filled with USABLE turns, not padded with dropped ones", () => {
  // 20 prior turns, every other one unanswered. A window taken before filtering would
  // yield 5 entries; taken after, it yields the 10 it promised.
  const prior = Array.from({ length: 20 }, (_, i) => ({
    index: i + 1,
    request: { text: `q${i + 1}`, ms: NOW + i * 1000 },
    response: i % 2 === 0 ? null : { text: `a${i + 1}`, ms: NOW + i * 1000 + 500 },
    tools: []
  }));
  const block = buildSessionBlock(prior, { sessionId: "s", startedAtMs: NOW, maxTurns: 10 });
  assert.equal(block.messages.length, 10);
  assert.equal(block.turn, 21);
  // Absolute numbering is kept, so dropping leaves gaps rather than renumbering.
  assert.deepEqual(block.messages.map((m) => m.turn), [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]);
});

test("an assistant turn that is a bare tool call does not wedge the chat", () => {
  // Copilot's most common shape for this: the planner emits a tool call with no prose, so
  // normalizeChat drops the empty assistant message and the user turn never closes.
  const seg = segment({
    userMessage: "now email it out",
    chatHistory: [
      chat("assistant", "", "2026-06-20T08:01:00Z"),
      chat("user", "summarise policy P-10234", "2026-06-20T08:00:00Z")
    ],
    previousToolOutputs: []
  }, { nowMs: NOW });
  const block = buildSessionBlock(seg.priorTurns, { sessionId: "s", startedAtMs: Date.parse("2026-06-20T08:00:00Z") });
  assert.equal(block.messages, undefined);
});

test("resolveStartedAt prefers the oldest chat entry (the seed greeting)", () => {
  const chatEvents = normalizeChat([
    chat("user", "later", "2026-06-20T08:10:00Z"),
    chat("assistant", "greeting", "2026-06-20T07:00:00Z")
  ]);
  assert.equal(resolveStartedAt(chatEvents, [], NOW), Date.parse("2026-06-20T07:00:00Z"));
});

// --- size -------------------------------------------------------------------

test("fitToBudget trims rather than failing, and keeps the pair invariant", () => {
  const big = "y".repeat(50000);
  const body = {
    context: {
      conversation: { messages: Array.from({ length: 30 }, (_, i) => ({ seq: i + 1, role: "tool", prompt: "p", timestamp: "t", response: big })) },
      hops: Array.from({ length: 30 }, (_, i) => ({ seq: i + 1, subject: {}, action: "invokeTool", resource: {}, time: "t" }))
    },
    inputValues: { blob: big },
    session: { id: "s", turn: 5, startedAt: "t", messages: Array.from({ length: 10 }, (_, i) => ({ turn: i + 1, request: { content: big }, response: { content: big } })) }
  };
  const { body: out, trimSteps } = fitToBudget(body, 20000);
  assert.ok(trimSteps.length > 0);
  assert.ok(Buffer.byteLength(JSON.stringify(out), "utf8") <= 20000);
  assert.equal(out.context.conversation?.messages?.length ?? 0, out.context.hops?.length ?? 0);
});

test("fitToBudget is a no-op under the limit", () => {
  const body = { context: {}, session: { id: "s", turn: 1 } };
  const { trimSteps } = fitToBudget(body, 900000);
  assert.deepEqual(trimSteps, []);
});
