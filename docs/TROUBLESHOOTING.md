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
| Every tool call blocked, reasonCode **103** | The service could not reach, authenticate to, or satisfy the Reva PDP | Read `errorKind` on the observability event: `transport` / `timeout` → check `REVA_PDP_URL` and egress; `auth` → the token is not a **v2** token ([INSTALL §7](INSTALL.md#7-a-note-on-the-reva-token)); `invalid-payload` → the PDP rejected the request body, and its own reason is on the event |
| One chat blocks every call from some point on, while other chats are fine | A prior turn in `session.messages` had no captured answer, so the PDP rejected the whole request with `400 invalid session: …response…is required` | Handled: unanswered turns are dropped before sending, and a turn answered by a tool call uses the tool result. If you see this, the payload gained a session entry from somewhere else — check `errorKind: invalid-payload` and the PDP's own reason on the event |
| PDP `401` | v1 token against the v2 endpoint | Issue a v2 token |
| PDP `403` *"requires a Tool resource, resolved …"* or *"requires action invokeTool"* | The entity **type** or the **action** is not what the schema pairs. Ids are free-form; types and actions are not | Fix the type/action pairing. This is not a policy decision, despite the 403 — the reason text is on the observability event |
| `400 managed context records are not supported at managed context.<key>` | A record was added to `context` outside the API's allowlist | Records are allowed only for `conversation`, `hops`, `chatHistory`, `environment` and `onBehalfOf`. Everything else must be a flat scalar or a scalar array. The error names the offending key |
| A Cedar policy publishes but never fires | Context attribute name mismatch | Cedar matches keys exactly and a missing key is not an error — it fails the `has` guard. Check `REVA_CONTEXT_ATTR_PREFIX` against your store |

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
| `errorKind` | which of transport / timeout / auth / invalid-payload / no-principal |
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
