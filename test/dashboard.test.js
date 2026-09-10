import test from "node:test";
import assert from "node:assert/strict";
import { buildObservabilityHtml } from "../src/core/observability-html.mjs";

/**
 * The dashboard is a browser script built by string interpolation inside a template
 * literal, which makes escaping a live hazard: a `\n` written for the browser's string is
 * consumed by the template literal instead and emitted as a real newline, producing an
 * unterminated string. The whole <script> then fails to parse and the page silently renders
 * nothing — no error server-side, a 200 response, and a blank panel.
 *
 * That happened. These tests exist so it cannot happen twice.
 */
function scriptOf(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(m, "the page must contain a script block");
  return m[1];
}

test("the emitted browser script is syntactically valid", () => {
  // new Function compiles without executing, so DOM references are irrelevant here.
  const body = scriptOf(buildObservabilityHtml("", 200));
  assert.doesNotThrow(() => new Function(body), "the dashboard script must parse in a browser");
});

test("no raw newline escapes into a browser string literal", () => {
  // The specific failure: a line ending mid-string, i.e. an odd number of unescaped quotes.
  for (const line of scriptOf(buildObservabilityHtml("https://example.test/prod", 50)).split("\n")) {
    const quotes = (line.match(/(?<!\\)"/g) || []).length;
    assert.equal(quotes % 2, 0, `unbalanced quotes, string runs off the end of: ${line.trim()}`);
  }
});

test("the page asks for the config token and embeds no stored data", () => {
  const html = buildObservabilityHtml("", 200);
  assert.match(html, /x-config-token/, "the page must prompt for and send the token");
  assert.ok(!/requestPayload/.test(html), "the shell must not embed any stored event");
});

test("a PUBLIC_API_BASE with a trailing slash does not produce a double slash", () => {
  const html = buildObservabilityHtml("https://example.test/prod/", 200);
  assert.doesNotThrow(() => new Function(scriptOf(html)));
  assert.ok(!html.includes("prod//"), "base URL joining must not double the slash");
});
