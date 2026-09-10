import { buildAuthConfigFromEnv, createAuth } from "../core/auth.mjs";
import {
  getHeader,
  parseAuthorization,
  withCorrelation,
  jsonResponse,
  unauthorized,
  methodNotAllowed
} from "../core/http.mjs";
import { appendObservabilityEvent } from "../storage/index.mjs";

const AUTH = createAuth(buildAuthConfigFromEnv(process.env));

export const handleValidate = async (req) => {
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
      path: "/validate",
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
      path: "/validate",
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

  const result = { isSuccessful: true, status: "OK" };
  await appendObservabilityEvent({
    path: "/validate",
    method: "POST",
    statusCode: 200,
    authType: authResult.authType || "unknown",
    correlationId: getHeader(headers, "x-ms-correlation-id") || null,
    requestPayload: {},
    response: result
  });
  return withCorrelation(headers, jsonResponse(200, result));
};
