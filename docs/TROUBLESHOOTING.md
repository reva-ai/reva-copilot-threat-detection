# Troubleshooting

Ordered roughly by when you hit them. Everything Entra-related surfaces when you press
**Save** in Power Platform admin center; everything PDP-related surfaces on the first real
tool call.

## Setup: Entra and Power Platform

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS650057` — invalid resource, empty valid-resource list | The CLI is not authorized to request a token for your API | [INSTALL §4.1](INSTALL.md#41-expose-an-api) step 3: add client `04b07795-8ddb-461a-bbee-02f9e1bf7b46` with `access_as_user` |
| `AADSTS700213` — no matching federated identity record | The asserted subject differs from the one you registered | Base64url-decode the subject in the error; create a credential for exactly that string. Wait 2–5 min. Delete-and-recreate rather than edit |
| `AADSTS500011` — resource principal not found in tenant | Application ID URI does not match the endpoint Power Platform requested, or is not on a verified domain | Set the Application ID URI to the exact base URL from [INSTALL §6](INSTALL.md#6-turn-it-on-in-power-platform), on a verified domain, and set `ENTRA_AUDIENCE` to the same string |
| `ExternalServiceTokenAcquisitionError` on Save | Entra could not issue a token at all | Work through the three rows above in order |
| `ExternalServiceTimeoutError`, or ~4s responses | Outbound 443 to `login.microsoftonline.com` blocked, or cold start | Open egress ([INSTALL §3](INSTALL.md#3-deploy-the-service)). JWKS is cached for 5 minutes after the first success |

> **Entra takes 2–5 minutes to propagate.** If you edit a federated credential and it still
> fails, delete it and recreate it rather than editing again — stale values persist.

## Runtime: the PDP

| Symptom | Cause | Fix |
|---|---|---|
| Copilot shows `securityWebhookBlocked`, but the event log shows **Allow** | The response arrived after Copilot's ~1000 ms budget, and the environment's error behaviour is **Block the query**. `serverBudgetExceeded` is host-side only and cannot see the network, so it reads `false` | [Blocked by Copilot while the log says Allow](#blocked-by-copilot-while-the-log-says-allow) below |
| Every tool call blocked, reasonCode **103** | The service could not reach, authenticate to, or satisfy the Reva PDP | Read `errorKind` on the observability event: `transport` / `timeout` → check `REVA_PDP_URL` and egress; `auth` → the token is not a **v2** token ([INSTALL §7](INSTALL.md#7-a-note-on-the-reva-token)); `invalid-payload` → the PDP rejected the request body, and its own reason is on the event |
| One chat blocks every call from some point on, while other chats are fine | A prior turn in `session.messages` had no captured answer, so the PDP rejected the whole request with `400 invalid session: …response…is required` | Handled: unanswered turns are dropped before sending, and a turn answered by a tool call uses the tool result. If you see this, the payload gained a session entry from somewhere else — check `errorKind: invalid-payload` and the PDP's own reason on the event |
| PDP `401` | v1 token against the v2 endpoint | Issue a v2 token |
| PDP `403` *"requires a Tool resource, resolved …"* or *"requires action invokeTool"* | The entity **type** or the **action** is not what the schema pairs. Ids are free-form; types and actions are not | Fix the type/action pairing. This is not a policy decision, despite the 403 — the reason text is on the observability event |
| `400 managed context records are not supported at managed context.<key>` | A record was added to `context` outside the API's allowlist | Records are allowed only for `conversation`, `hops`, `chatHistory`, `environment` and `onBehalfOf`. Everything else must be a flat scalar or a scalar array. The error names the offending key |
| Tool calls blocked intermittently, `errorKind: upstream-blocked`, `responsePreview` is HTML | A CDN or WAF in front of the PDP rejected the request; it never reached the PDP | See [A WAF in front of the PDP](#a-waf-in-front-of-the-pdp) below. Not a payload problem and not a policy decision — the PDP has no decision-log entry for it at all |
| A Cedar policy publishes but never fires | Context attribute name mismatch | Cedar matches keys exactly and a missing key is not an error — it fails the `has` guard. Check `REVA_CONTEXT_ATTR_PREFIX` against your store |

## Blocked by Copilot while the log says Allow

**Symptom.** Copilot shows `securityWebhookBlocked` — *"This message was blocked by threat
detection tools configured by your admin"* — but the observability event for the same
conversation records **Allow**, a short `serverTotalMs`, and `serverBudgetExceeded: false`.

Match the `Conversation Id` in Copilot's error against
`requestPayload.conversationMetadata.conversationId` on the event. If they match and the event
says Allow, the decision was fine and the *delivery* was not.

**Cause.** The answer arrived after Copilot's ~1000 ms budget. What happens then is set by
**Set error behavior** in the Power Platform admin center: the documented default is to
proceed as if you had answered *allow*, but an environment set to **Block the query** refuses
instead — so being slow looks exactly like a policy denial.

`serverBudgetExceeded` is measured host-side. It covers the route, and with `gatewayMs` it
covers cold-start init and queueing too — but it cannot see the network between Copilot and
your endpoint, which on a distant deployment is the larger half.

**Confirming it.** Time the round trip from a machine near the Power Platform region:

```bash
curl -s -o /dev/null -X POST "https://<your endpoint>/analyze-tool-execution?api-version=2025-05-01" \
  -w "connect %{time_connect}s  tls %{time_appconnect}s  ttfb %{time_starttransfer}s  total %{time_total}s\n"
```

A 401 is fine — the timings are the point. If `time_appconnect` alone is a large fraction of a
second, TLS is terminating far from the caller and most of the budget is gone before your
service is reached. One measured example, an Indian Power Platform region against a
`us-east-1` gateway: connect ~230 ms, TLS ~240 ms more, **760–875 ms for a complete round trip
with no application work at all.**

**Fix.** Deploy in the region nearest the Power Platform environment, or put a CDN with edge
TLS termination in front so the handshake completes near the caller. See
[INSTALL.md](INSTALL.md).

Switching the error behaviour to *"Allow the agent to respond"* stops the blocks, but it does
so by not enforcing whenever the service is slow. That is a fail-open choice, worth making
deliberately rather than as a workaround.

## A WAF in front of the PDP

**Symptom.** Tool calls are blocked with reasonCode 103. The observability event shows
`errorKind: upstream-blocked`, an `httpStatus` of 403, and a `responsePreview` that is HTML
rather than JSON — typically:

```
403 ERROR / The request could not be satisfied. / Request blocked.
```

The PDP has **no decision-log entry** for these requests, while the calls either side of
them appear normally. That asymmetry is the tell: the request never arrived.

**Cause.** A web application firewall between this service and the PDP matched the request
body against SQL-injection, cross-site-scripting or path-traversal signatures and rejected
it at the edge. Confirmed with AWS WAF managed rule groups on a CloudFront distribution;
any equivalent content-inspecting WAF behaves the same way.

**Why it hits this service specifically.** The payload forwarded to the PDP is
attacker-controlled by design. It carries the user's prompt, the planner's reasoning, the
output of previously invoked tools, and the contents of documents those tools fetched. A
guardrail evaluating prompt injection has to *see* the injection attempt. So a
content-pattern WAF on this route fires on precisely the traffic the guardrails exist to
score, and blocks the request that most needed evaluating.

Strings that trip common managed rules — all of which can legitimately appear inside a
search result, a support ticket, a fetched web page or a code snippet:

| Content | Rule group |
|---|---|
| `' OR 1=1 --`, `UNION SELECT …` | SQL injection |
| `<script>…</script>`, `<img src=x onerror=…>`, `javascript:` URIs | Cross-site scripting |
| `../../../../etc/passwd` | Local file inclusion |

It is also **intermittent**, which makes it easy to misdiagnose. WAF body inspection is
capped — 16 KB on CloudFront by default — so the same content passes or fails depending on
how far into the conversation it lands. Early turns get blocked; the same text later in a
long conversation sails through. Total body size is not the trigger: a large payload of
ordinary prose is fine.

**Fix.** Exempt the PDP evaluation route from content-inspection rules. On AWS WAF, scope
down the managed rule groups so they do not apply to `POST /pdp/v2/ai/evaluation`, or add a
higher-priority `Allow` rule for that path. The equivalent exists in every WAF product.

This is infrastructure in front of the PDP, so on a Reva-hosted PDP it is a request to Reva;
on a self-hosted one it is your own configuration.

**What the service does meanwhile.** It fails closed — the call is blocked, not permitted.
`upstream-blocked` exists as a separate `errorKind` so this is not reported as
`invalid-payload`, which would blame this service's request builder for someone else's
rejection and send you looking in the wrong place.

**Confirming it.** Replay a request with a known-triggering string in the body. A WAF block
answers with `content-type: text/html` and no `x-amzn-requestid`; a real PDP response is
always JSON, on every status it owns — including denials and its own payload rejections.

## Nothing reaches the service at all

**The webhook only fires for tool calls.** If the agent answers from the model alone, this
service is never invoked. Add an explicit instruction such as *"When the user asks for X,
always invoke the Y tool first. Do not answer without tool output."*

**It only applies to generative agents using generative orchestration.** Classic agents
never call it. And it is configured **per environment** — there is no tenant-wide switch, so
a new environment starts unprotected until someone turns it on.

## Reading the evidence

Enable the dashboard temporarily (`ENABLE_OBSERVABILITY=true` plus a `CONFIG_API_TOKEN`) and
every request records:

| Field | Tells you |
|---|---|
| `errorKind` | which of transport / timeout / auth / invalid-payload / upstream-blocked / no-principal |
| `callerAppId` | the application whose token we accepted — compare with `ENTRA_ALLOWED_APP_IDS` |
| `entityResolution` | how each id resolved: `id-map`, `name-map` or `slug` |
| `payloadShape` | `conversation` and `hops` counts — **they must be equal** |
| `latency.budgetExceeded` | whether Copilot had already given up before we answered |
| `monitorWouldDeny` | in monitor mode, the denial that was recorded and not enforced |
| `trimSteps` | what was dropped to stay under the PDP's 1 MiB limit |

Conversation content is redacted by default. For a debugging session set
`OBS_STORE_PROMPTS=true`, and turn it off afterwards — the store then holds personal data.

## Guardrail verdicts are not in the response

The synchronous answer is `{decision}` and nothing else: no score, no chain, no reason. If
Reva's guardrails (prompt injection, intent drift) are attached in **monitor** mode they run
and record but never change the answer. Their verdicts are visible **only** in the Reva
decision log.

So an allow here is not an all-clear, and you cannot assert on guardrail behaviour from this
side. Correlate using the `traceparent`: its trace id derives from the Copilot
`conversationId`, so every decision in one chat shares a trace.
