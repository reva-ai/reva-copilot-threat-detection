import { getHeader, unauthorized, badRequest } from "./http.mjs";

export function configApiToken() {
  return (process.env.CONFIG_API_TOKEN || "").trim();
}

export function requireConfigApiAuth(headers) {
  const expected = configApiToken();
  if (!expected) {
    return badRequest(
      "Runtime config API is disabled.",
      "Set CONFIG_API_TOKEN to enable /config/policy endpoint."
    );
  }
  const provided = getHeader(headers, "x-config-token").trim();
  if (!provided || provided !== expected) {
    return unauthorized("Missing or invalid x-config-token.");
  }
  return null;
}
