/**
 * The observability dashboard. OPT-IN — no adapter mounts these unless explicitly enabled,
 * because a deployment that never turns them on has no such surface to protect.
 *
 * When enabled, the three DATA routes require x-config-token and disable themselves without
 * one. The page itself is reachable unauthenticated: a browser cannot set a header on a
 * navigation, and the page carries no data — it prompts for the token and holds it in the
 * tab. Conversation content is redacted at write time regardless (see core/redact.mjs), so
 * even an exposed store does not hold prompts.
 */
import {
  listObservabilityEvents,
  clearObservabilityEvents,
  getPolicyConfig,
  sanitizePolicyConfig,
  getObsMaxEvents
} from "../storage/index.mjs";
import { requireConfigApiAuth } from "../core/config-token.mjs";
import { buildObservabilityHtml } from "../core/observability-html.mjs";
import { withCorrelation, jsonResponse, htmlResponse, methodNotAllowed } from "../core/http.mjs";

export const handleObservabilityPage = async (req) => {
  const headers = req.headers || {};
  if ((req.method || "GET") !== "GET") return withCorrelation(headers, methodNotAllowed());
  const publicBase = (process.env.PUBLIC_API_BASE || "").trim();
  return withCorrelation(headers, htmlResponse(200, buildObservabilityHtml(publicBase, await getObsMaxEvents())));
};

export const handleObservabilityEvents = async (req) => {
  const headers = req.headers || {};
  if ((req.method || "GET") !== "GET") return withCorrelation(headers, methodNotAllowed());
  const denied = requireConfigApiAuth(headers);
  if (denied) return withCorrelation(headers, denied);
  return withCorrelation(headers, jsonResponse(200, { events: await listObservabilityEvents(await getObsMaxEvents()) }));
};

export const handleObservabilityEventsClear = async (req) => {
  const headers = req.headers || {};
  if ((req.method || "GET") !== "DELETE") return withCorrelation(headers, methodNotAllowed());
  const denied = requireConfigApiAuth(headers);
  if (denied) return withCorrelation(headers, denied);
  await clearObservabilityEvents();
  return withCorrelation(headers, jsonResponse(200, { cleared: true }));
};

export const handleObservabilityPolicy = async (req) => {
  const headers = req.headers || {};
  if ((req.method || "GET") !== "GET") return withCorrelation(headers, methodNotAllowed());
  const denied = requireConfigApiAuth(headers);
  if (denied) return withCorrelation(headers, denied);
  const row = await getPolicyConfig();
  return withCorrelation(
    headers,
    jsonResponse(200, {
      config: await sanitizePolicyConfig(row),
      updatedAt: row.updatedAt,
      configApiEnabled: Boolean((process.env.CONFIG_API_TOKEN || "").trim())
    })
  );
};
