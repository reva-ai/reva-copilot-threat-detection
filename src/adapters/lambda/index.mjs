/**
 * AWS Lambda adapter.
 *
 * Translates an API Gateway event into the neutral request the routes take, and the neutral
 * response back into what Lambda expects. Every route is exported as its own handler so a
 * deployment can put each behind its own function and IAM role — which is how the
 * observability routes end up genuinely separable from the authorization path rather than
 * separable in principle.
 *
 * Set the Lambda handler to `index.<name>` for the route you are deploying, or use the
 * per-route entry files alongside this one if your tooling expects `index.handler`.
 */
import { handleValidate } from "../../routes/validate.mjs";
import { handleAnalyzeToolExecution } from "../../routes/analyze-tool-execution.mjs";
import { handleConfigPolicyRead, handleConfigPolicyWrite } from "../../routes/config-policy.mjs";

/** API Gateway (REST and HTTP API) and Function URL events all reduce to this. */
export function toRequest(event) {
  const method = event?.requestContext?.http?.method || event?.httpMethod || "GET";
  const rawPath = event?.rawPath || event?.path || "/";
  const body = event?.isBase64Encoded && event?.body
    ? Buffer.from(event.body, "base64").toString("utf8")
    : event?.body || "";
  return { method, path: rawPath, headers: event?.headers || {}, body };
}

/** Wrap a route so it presents as a Lambda handler. */
export function lambdaHandler(route) {
  return async (event) => {
    const out = await route(toRequest(event));
    return { statusCode: out.statusCode, headers: out.headers || {}, body: out.body ?? "" };
  };
}

export const validate = lambdaHandler(handleValidate);
export const analyzeToolExecution = lambdaHandler(handleAnalyzeToolExecution);
export const configPolicyRead = lambdaHandler(handleConfigPolicyRead);
export const configPolicyWrite = lambdaHandler(handleConfigPolicyWrite);

/**
 * The observability routes are imported lazily and only when enabled, so a function that
 * does not serve them never loads the dashboard code at all.
 */
export async function observabilityHandlers() {
  if (process.env.ENABLE_OBSERVABILITY !== "true") {
    throw new Error("Observability routes are disabled. Set ENABLE_OBSERVABILITY=true to mount them.");
  }
  const obs = await import("../../routes/observability.mjs");
  return {
    page: lambdaHandler(obs.handleObservabilityPage),
    events: lambdaHandler(obs.handleObservabilityEvents),
    eventsClear: lambdaHandler(obs.handleObservabilityEventsClear)
  };
}
