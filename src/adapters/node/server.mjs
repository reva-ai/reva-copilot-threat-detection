#!/usr/bin/env node
/**
 * A plain Node HTTP server exposing the two endpoints Copilot Studio calls.
 *
 * Runs anywhere Node runs — Azure App Service, Azure Container Apps, ECS or Fargate,
 * Kubernetes, a VM, your laptop. It uses only `node:http`, so the whole package has no
 * runtime dependencies unless you opt into DynamoDB storage.
 *
 * Start it:
 *   ENTRA_TENANT_ID=... ENTRA_AUDIENCE=... REVA_PDP_URL=... \
 *   REVA_POLICY_STORE_ID=... REVA_PDP_TOKEN=... node src/adapters/node/server.mjs
 *
 * TLS is deliberately not handled here. Copilot Studio requires HTTPS, and terminating it
 * belongs to the platform in front of this process — App Service, an ingress controller, a
 * load balancer. A server that also did certificates would be worse at both jobs.
 */
import http from "node:http";
import { handleValidate } from "../../routes/validate.mjs";
import { handleAnalyzeToolExecution } from "../../routes/analyze-tool-execution.mjs";
import { handleConfigPolicyRead, handleConfigPolicyWrite } from "../../routes/config-policy.mjs";
import { notFound, jsonResponse } from "../../core/http.mjs";

/** Bodies larger than this are refused before being read into memory. */
const MAX_BODY_BYTES = Number(process.env.MAX_REQUEST_BYTES || 2 * 1024 * 1024);

/**
 * The routes Copilot Studio needs, and nothing else. Everything optional is added below
 * only when its feature flag is on, so the default deployment exposes the smallest surface
 * that works.
 */
const routes = [
  { method: "POST", path: "/validate", handler: handleValidate },
  { method: "POST", path: "/analyze-tool-execution", handler: handleAnalyzeToolExecution }
];

if (process.env.ENABLE_CONFIG_API === "true") {
  routes.push(
    { method: "GET", path: "/config/policy", handler: handleConfigPolicyRead },
    { method: "PUT", path: "/config/policy", handler: handleConfigPolicyWrite }
  );
}

// Opt-in, and off by default. These serve the record of every authorization decision; a
// deployment that does not enable them cannot leak from them.
if (process.env.ENABLE_OBSERVABILITY === "true") {
  const obs = await import("../../routes/observability.mjs");
  routes.push(
    { method: "GET", path: "/observability", handler: obs.handleObservabilityPage },
    { method: "GET", path: "/observability/events", handler: obs.handleObservabilityEvents },
    { method: "DELETE", path: "/observability/events", handler: obs.handleObservabilityEventsClear }
  );
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        // Destroy rather than keep buffering: an oversized body is refused, not absorbed.
        reject(Object.assign(new Error("Request body too large."), { tooLarge: true }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Path only — Copilot appends `?api-version=…`, which the spec says not to validate. */
function pathOf(url) {
  const q = url.indexOf("?");
  return q === -1 ? url : url.slice(0, q);
}

export function createServer() {
  return http.createServer(async (req, res) => {
    // Taken before the body is read, so the measured span covers reading it. There is no
    // gateway in front of this adapter, so this is the closest equivalent to one.
    const receivedAtMs = Date.now();
    let out;
    try {
      const path = pathOf(req.url || "/");
      const route = routes.find((r) => r.path === path && r.method === req.method);

      if (!route) {
        // 405 rather than 404 when the path exists under another method, so a wrong verb is
        // diagnosable instead of looking like a deployment problem.
        const pathExists = routes.some((r) => r.path === path);
        out = pathExists
          ? jsonResponse(405, { errorCode: 4050, message: "Method not allowed.", httpStatus: 405 })
          : notFound();
      } else {
        const body = await readBody(req);
        out = await route.handler({
          method: req.method,
          path,
          headers: req.headers,
          body,
          receivedAtMs
        });
      }
    } catch (err) {
      if (err?.tooLarge) {
        out = jsonResponse(413, { errorCode: 4130, message: "Request body too large.", httpStatus: 413 });
      } else {
        // Never surface an internal error message to the caller: it is Microsoft's platform
        // on the other end, and the detail belongs in our logs, not in their response.
        console.error("[reva-copilot-threat-detection] unhandled error:", err);
        out = jsonResponse(500, { errorCode: 5000, message: "Internal error.", httpStatus: 500 });
      }
    }

    res.writeHead(out.statusCode, out.headers || {});
    res.end(out.body ?? "");
  });
}

// Started directly rather than imported for tests.
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT || 8080);
  const host = process.env.BIND_HOST || "0.0.0.0";
  createServer().listen(port, host, () => {
    const enabled = routes.map((r) => `${r.method} ${r.path}`).join(", ");
    console.log(`[reva-copilot-threat-detection] listening on ${host}:${port}`);
    console.log(`[reva-copilot-threat-detection] routes: ${enabled}`);
  });
}
