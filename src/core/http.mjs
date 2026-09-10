export function getHeader(headers, name) {
  if (!headers) return "";
  const lower = name.toLowerCase();
  const found = Object.keys(headers).find((k) => k.toLowerCase() === lower);
  return found ? String(headers[found]) : "";
}

export function parseAuthorization(headers) {
  return parseAuthorizationValue(getHeader(headers, "authorization"));
}

export function parseAuthorizationValue(headerValue) {
  if (!headerValue) return "";
  const [scheme, token] = headerValue.split(" ");
  if (!scheme || scheme.toLowerCase() !== "bearer" || !token) return "";
  return token.trim();
}

export function jsonResponse(statusCode, obj, extraHeaders = {}) {
  const payload = JSON.stringify(obj, null, 2);
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders
    },
    body: payload
  };
}

export function htmlResponse(statusCode, html, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...extraHeaders
    },
    body: html
  };
}

export function withCorrelation(headers, response) {
  const cid = getHeader(headers, "x-ms-correlation-id");
  if (!cid) return response;
  return {
    ...response,
    headers: {
      ...response.headers,
      "x-ms-correlation-id": cid
    }
  };
}

export function unauthorized(diagnostics) {
  return jsonResponse(401, {
    errorCode: 4010,
    message: "Unauthorized.",
    httpStatus: 401,
    diagnostics
  });
}

export function notFound() {
  return jsonResponse(404, {
    errorCode: 4040,
    message: "Endpoint not found.",
    httpStatus: 404
  });
}

export function methodNotAllowed() {
  return jsonResponse(405, {
    errorCode: 4050,
    message: "Method not allowed.",
    httpStatus: 405
  });
}

export function badRequest(message, diagnostics) {
  return jsonResponse(400, {
    errorCode: 4000,
    message,
    httpStatus: 400,
    diagnostics
  });
}

/**
 * Routes take a NORMALISED request and return a plain `{statusCode, headers, body}`.
 * Neither shape belongs to any host: the Lambda adapter translates an API Gateway event
 * into one and the result back out, the Node adapter does the same for an IncomingMessage,
 * and a future adapter needs nothing from the routes themselves.
 *
 *   { method: "POST", path: "/analyze-tool-execution", headers: {...}, body: "<raw string>" }
 *
 * Body stays a string rather than being parsed here, because a route that does not need it
 * should not pay to parse it, and because `validate` is specified to receive an empty body.
 */
export function parseJsonBody(rawBody) {
  if (!rawBody) return {};
  try {
    return JSON.parse(rawBody);
  } catch (e) {
    throw new Error(`Invalid JSON body. ${e.message}`);
  }
}
