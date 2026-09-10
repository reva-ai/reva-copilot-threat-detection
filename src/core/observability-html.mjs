export function buildObservabilityHtml(publicApiBase, obsMaxEvents, eventsStorageNote = "DynamoDB-backed") {
  const base = publicApiBase || "";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Threat Detection Observability</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #111827; background: #f9fafb; }
      h1 { margin: 0 0 12px 0; font-size: 24px; }
      p { margin: 0 0 16px 0; color: #4b5563; }
      .toolbar { display: flex; gap: 8px; margin-bottom: 16px; }
      button { padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 8px; background: white; cursor: pointer; }
      button:hover { background: #f3f4f6; }
      .event { border: 1px solid #d1d5db; border-radius: 10px; background: white; margin-bottom: 12px; overflow: hidden; }
      .meta { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; display: flex; gap: 12px; flex-wrap: wrap; font-size: 13px; background: #f9fafb; }
      pre { margin: 0; padding: 12px; overflow: auto; font-size: 12px; background: #111827; color: #f9fafb; }
      .empty { color: #6b7280; padding: 16px; border: 1px dashed #d1d5db; border-radius: 10px; background: white; }
      .badge { display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 12px; }
      .allow { background: #dcfce7; color: #166534; }
      .block { background: #fee2e2; color: #991b1b; }
      .na { background: #e5e7eb; color: #374151; }
      .status-line { margin: 12px 0; font-size: 14px; min-height: 20px; color: #374151; }
      .status-line.ok { color: #166534; }
      .status-line.err { color: #991b1b; }
    </style>
  </head>
  <body>
    <h1>Threat Detection Observability</h1>
    <p>Shows recent webhook requests and decisions (latest ${obsMaxEvents} events, ${eventsStorageNote}).</p>
    <div class="toolbar">
      <button id="refreshBtn">Refresh</button>
      <button id="autoBtn">Auto refresh: On</button>
      <button id="clearBtn">Clear events</button>
      <button id="otelExportBtn" type="button">Send to Datadog (OTEL)</button>
    </div>
    <div class="status-line" id="otelStatus" aria-live="polite"></div>
    <div id="events"></div>
    <script>
      const API_BASE = ${JSON.stringify(base)};
      let auto = true;
      let timer = null;

      function apiPath(path) {
        if (!API_BASE) return path;
        let b = API_BASE;
        while (b.endsWith("/")) b = b.slice(0, -1);
        return b + path;
      }

      // The data routes require x-config-token. The page itself carries no data and stays
      // reachable without one — a browser cannot set a header on a navigation — so the token
      // is asked for once, held in memory for this tab only, and never written to storage.
      let sessionToken = null;
      function authHeaders() {
        if (!sessionToken) {
          const entered = prompt(
            "Enter the config API token (x-config-token) to view observability data.\n" +
            "It is held for this tab only and is never stored."
          );
          sessionToken = entered == null ? "" : String(entered).trim();
        }
        return sessionToken ? { "x-config-token": sessionToken } : {};
      }

      function forgetToken() { sessionToken = null; }

      function render(events) {
        const root = document.getElementById("events");
        if (!events.length) {
          root.innerHTML = '<div class="empty">No events yet. Trigger /validate or /analyze-tool-execution first.</div>';
          return;
        }

        root.innerHTML = events.map((event) => {
          const decision = event.response && typeof event.response.blockAction === "boolean"
            ? (event.response.blockAction ? "Block" : "Allow")
            : "N/A";
          const decisionClass = decision === "Allow" ? "allow" : decision === "Block" ? "block" : "na";
          return '<div class="event">' +
            '<div class="meta">' +
            '<strong>#' + event.id + '</strong>' +
            '<span>' + new Date(event.timestamp).toLocaleString() + '</span>' +
            '<span><strong>Path:</strong> ' + event.path + '</span>' +
            '<span><strong>Status:</strong> ' + event.statusCode + '</span>' +
            '<span><strong>Auth:</strong> ' + event.authType + '</span>' +
            '<span><strong>Correlation:</strong> ' + (event.correlationId || '-') + '</span>' +
            '<span class="badge ' + decisionClass + '">' + decision + '</span>' +
            '</div>' +
            '<pre>' + JSON.stringify(event, null, 2) + '</pre>' +
            '</div>';
        }).join('');
      }

      async function fetchEvents() {
        const response = await fetch(apiPath("/observability/events"), { headers: authHeaders() });
        if (response.status === 401) { forgetToken(); throw new Error("Unauthorized — check the config API token."); }
        const payload = await response.json();
        render(payload.events || []);
      }

      async function refreshAll() {
        await fetchEvents();
      }

      async function clearEvents() {
        await fetch(apiPath("/observability/events"), { method: 'DELETE', headers: authHeaders() });
        await refreshAll();
      }

      function setOtelStatus(text, kind) {
        const el = document.getElementById("otelStatus");
        el.textContent = text || "";
        el.className = "status-line" + (kind === "ok" ? " ok" : kind === "err" ? " err" : "");
      }

      document.getElementById("otelExportBtn").addEventListener("click", async () => {
        const token = prompt(
          "Enter config API token (x-config-token) to authorize export. It is not stored in the page."
        );
        if (token == null || !String(token).trim()) {
          setOtelStatus("Export cancelled.", "err");
          return;
        }
        setOtelStatus("Sending…");
        try {
          const response = await fetch(apiPath("/observability/otel-export"), {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-config-token": String(token).trim()
            },
            body: "{}"
          });
          const raw = await response.text();
          let payload;
          try {
            payload = raw ? JSON.parse(raw) : {};
          } catch {
            payload = { message: raw };
          }
          if (!response.ok) {
            setOtelStatus(
              "Export failed: HTTP " + response.status + " — " + (payload.message || JSON.stringify(payload)),
              "err"
            );
            return;
          }
          if (payload.ok) {
            setOtelStatus("OK — sent " + (payload.sentCount != null ? payload.sentCount : "?") + " log record(s) to OTLP collector.", "ok");
          } else {
            setOtelStatus("Unexpected response: " + JSON.stringify(payload), "err");
          }
        } catch (e) {
          setOtelStatus("Export failed: " + (e && e.message ? e.message : String(e)), "err");
        }
      });

      document.getElementById("refreshBtn").addEventListener("click", refreshAll);
      document.getElementById("clearBtn").addEventListener("click", clearEvents);
      document.getElementById("autoBtn").addEventListener("click", () => {
        auto = !auto;
        document.getElementById("autoBtn").textContent = 'Auto refresh: ' + (auto ? 'On' : 'Off');
        if (auto && !timer) {
          timer = setInterval(() => refreshAll().catch(() => {}), 2000);
        } else if (!auto && timer) {
          clearInterval(timer);
          timer = null;
        }
      });

      refreshAll().catch(console.error);
      timer = setInterval(() => {
        if (auto) refreshAll().catch(() => {});
      }, 2000);
    </script>
  </body>
</html>`;
}
