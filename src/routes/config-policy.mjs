/**
 * Read and update the runtime blocked-terms policy.
 *
 * Guarded by CONFIG_API_TOKEN and DISABLED when it is unset. These routes change what the
 * plugin blocks, so an unconfigured deployment must not expose them at all — the failure
 * mode of forgetting to set a token is a switched-off endpoint, never an open one.
 */
import {
  getPolicyConfig,
  putPolicyConfig,
  sanitizePolicyConfig,
  appendObservabilityEvent,
  getStorage
} from "../storage/index.mjs";
import { requireConfigApiAuth } from "../core/config-token.mjs";
import {
  getHeader,
  withCorrelation,
  jsonResponse,
  methodNotAllowed,
  badRequest,
  parseJsonBody
} from "../core/http.mjs";

export const handleConfigPolicyRead = async (req) => {
  const headers = req.headers || {};

  const authErr = requireConfigApiAuth(headers);
  if (authErr) return withCorrelation(headers, authErr);
  if ((req.method || "GET") !== "GET") return withCorrelation(headers, methodNotAllowed());

  const row = await getPolicyConfig();
  return withCorrelation(
    headers,
    jsonResponse(200, { config: await sanitizePolicyConfig(row), updatedAt: row.updatedAt })
  );
};

export const handleConfigPolicyWrite = async (req) => {
  const headers = req.headers || {};

  const authErr = requireConfigApiAuth(headers);
  if (authErr) return withCorrelation(headers, authErr);
  if ((req.method || "GET") !== "PUT") return withCorrelation(headers, methodNotAllowed());

  let payload;
  try {
    payload = parseJsonBody(req.body);
  } catch (err) {
    return withCorrelation(headers, badRequest("Invalid request body.", err.message));
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return withCorrelation(headers, badRequest("Request body must be a JSON object."));
  }

  try {
    const store = await getStorage();
    const current = await getPolicyConfig();
    const nextConfig = {
      blockedTerms:
        payload.blockedTerms === undefined
          ? current.blockedTerms
          : store.normalizeStringList(payload.blockedTerms, "blockedTerms"),
      blockedToolNames:
        payload.blockedToolNames === undefined
          ? current.blockedToolNames
          : store.normalizeStringList(payload.blockedToolNames, "blockedToolNames")
    };

    const saved = await putPolicyConfig(nextConfig);
    const result = {
      updated: true,
      config: await sanitizePolicyConfig(saved),
      updatedAt: saved.updatedAt
    };

    await appendObservabilityEvent({
      path: "/config/policy",
      method: "PUT",
      statusCode: 200,
      authType: "config-token",
      correlationId: getHeader(headers, "x-ms-correlation-id") || null,
      // The policy itself, not user data — safe to record verbatim, and the audit trail for
      // "who changed what the gateway blocks" is worth having.
      requestPayload: payload,
      response: result
    });
    return withCorrelation(headers, jsonResponse(200, result));
  } catch (err) {
    return withCorrelation(headers, badRequest("Invalid config payload.", err.message));
  }
};
