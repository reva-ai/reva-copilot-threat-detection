# Lambda environment variables

Per-function variables for the nine Copilot threat-detection Lambdas. Replace placeholders with your real values. Do not commit secrets.

## Where you must supply real values vs where defaults apply

### A. Keys that need **your** data (look up or generate)

Set these from **your** AWS / Entra / API Gateway / policy choices. There is no universal “correct” string except what matches **your** registrations and table.

| Key | What to put |
|-----|-------------|
| `DYNAMODB_TABLE_NAME` | Name of **your** DynamoDB table (same on all Lambdas that use DynamoDB). |
| `ENTRA_TENANT_ID` | **Your** Microsoft Entra *Directory (tenant) ID* (GUID from Azure portal). |
| `ENTRA_AUDIENCE` | **Your** API app’s expected JWT `aud` (from the Entra app registration Copilot uses — often `api://...` or the application ID URI). |
| `CONFIG_API_TOKEN` | **Your** secret for `x-config-token` (generate, e.g. 32+ random bytes; use on config read/write and **observability-otel-export**). |
| `PUBLIC_API_BASE` | **Your** API Gateway base URL, no trailing slash (include stage if required), if the observability page cannot use relative paths. |
| `BLOCKED_TERMS` | **Your** comma-separated blocked phrases (policy seed; keep identical on every Lambda that sets them). |
| `BLOCKED_TOOL_NAMES` | **Your** comma-separated exact tool names to block (policy seed; keep identical). |
| `AUTH_TOKEN` | **Your** static bearer string (only when `ALLOW_INSECURE_LOCAL_AUTH=true` for dev). |
| `ALLOW_INSECURE_LOCAL_AUTH` | Literal `true` only for non-production testing (replaces Entra on the two webhook Lambdas). |
| `REVA_DECISION_LOG_QUERY_URL` | Full URL for **`POST`** Reva decision log query (e.g. `https://api….reva.ai/api/v1/logs/decision/query`). **Only** for `observability-otel-export`. |
| `OTEL_COLLECTOR_OTLP_HTTP_URL` | OTLP HTTP logs URL for your Collector, e.g. `http://<host>:4318/v1/logs`. **Only** for `observability-otel-export`. |

### Optional IdP / issuer overrides

| Key | When to set |
|-----|-------------|
| `ENTRA_ISSUER` | If tokens use an issuer you must pin explicitly. |
| `ENTRA_JWKS_URI` | If JWKS must be fetched from a non-standard URL. |

### B. Keys with **built-in defaults** (omit unless you want to override)

If you **do not** set these, the code uses the default below (`shared/auth.mjs`, `shared/storage.mjs`).

| Key | Default when unset | Override only if… |
|-----|--------------------|-------------------|
| `JWT_CLOCK_SKEW_SECONDS` | `60` | You need more/less clock tolerance for JWT `exp`/`nbf`. |
| `JWKS_CACHE_TTL_MS` | `300000` (5 minutes) | You want JWKS cached shorter/longer. |
| `OBS_MAX_EVENTS` | `200` (effective minimum `10`) | You want a different observability event cap. |

You do **not** need to define `JWT_CLOCK_SKEW_SECONDS` or `JWKS_CACHE_TTL_MS` for normal production; the values above are already applied in code.

---

## Consolidated keys (all names)

These are the only env var **keys** used anywhere in this project:

| Key | Typically set on |
|-----|------------------|
| `DYNAMODB_TABLE_NAME` | Every Lambda **except** `observability` and `observability-otel-export` |
| `ENTRA_TENANT_ID` | `validate`, `analyze-tool-execution` (production) |
| `ENTRA_AUDIENCE` | `validate`, `analyze-tool-execution` (production) |
| `ENTRA_ISSUER` | Optional — `validate`, `analyze-tool-execution` |
| `ENTRA_JWKS_URI` | Optional — `validate`, `analyze-tool-execution` |
| `JWT_CLOCK_SKEW_SECONDS` | Optional — `validate`, `analyze-tool-execution` |
| `JWKS_CACHE_TTL_MS` | Optional — `validate`, `analyze-tool-execution` |
| `ALLOW_INSECURE_LOCAL_AUTH` | Dev only — `validate`, `analyze-tool-execution` |
| `AUTH_TOKEN` | Dev only — `validate`, `analyze-tool-execution` |
| `BLOCKED_TERMS` | `analyze-tool-execution`, `observability-policy`, `config-policy-read`, `config-policy-write` |
| `BLOCKED_TOOL_NAMES` | Same as `BLOCKED_TERMS` |
| `OBS_MAX_EVENTS` | `observability`, `observability-events-list` |
| `PUBLIC_API_BASE` | `observability` (optional) |
| `CONFIG_API_TOKEN` | `config-policy-read`, `config-policy-write`, `observability-otel-export`; optional on `observability-policy` |
| `REVA_DECISION_LOG_QUERY_URL` | `observability-otel-export` |
| `REVA_PDP_URL`, `REVA_POLICY_STORE_ID`, `REVA_PDP_TOKEN`, `REVA_PDP_ORIGIN`, `REVA_PDP_SURFACE_RESPONSE` | `analyze-tool-execution` |
| `REVA_PDP_TIMEOUT_MS`, `REVA_FAIL_OPEN`, `REVA_MODE` | `analyze-tool-execution` |
| `REVA_REQUIRE_BODY_PRINCIPAL` | `analyze-tool-execution` |
| `REVA_PRINCIPAL_ID_MAP`, `REVA_AGENT_ID_MAP`, `REVA_TOOL_ID_MAP`, `REVA_USER_GROUPS_MAP` | Optional — `analyze-tool-execution` |
| `REVA_SEND_COPILOT_CONTEXT`, `REVA_SEND_SCHEMA_CONTEXT`, `REVA_ENVIRONMENT_MAP` | `analyze-tool-execution` |
| `ENTRA_ALLOWED_APP_IDS` | `validate`, `analyze-tool-execution` |
| `OBS_STORE_PROMPTS` | `analyze-tool-execution` |
| `REVA_CONTEXT_ATTR_PREFIX`, `REVA_INCLUDE_PLANNER_THOUGHT`, `REVA_SESSION_MAX_TURNS`, `REVA_SESSION_MAX_CHARS` | `analyze-tool-execution` |
| `REVA_DECISION_LOG_BODY_JSON` | Optional JSON string for the Reva request body (defaults to a demo filter excluding `application_name == Reva`) |
| `OTEL_COLLECTOR_OTLP_HTTP_URL` | `observability-otel-export` |

**Production Copilot path (minimal):** `DYNAMODB_TABLE_NAME`, `ENTRA_TENANT_ID`, `ENTRA_AUDIENCE`, `BLOCKED_TERMS`, `BLOCKED_TOOL_NAMES`, `CONFIG_API_TOKEN`, and usually `OBS_MAX_EVENTS` + `PUBLIC_API_BASE` for the dashboard.

**Policy seed (`BLOCKED_TERMS`, `BLOCKED_TOOL_NAMES`)**  
Use the **same** comma-separated values on every Lambda that defines them. They only apply when the DynamoDB policy row is **missing** (first cold start / empty table). Whichever function calls `getPolicyConfig()` first writes that row; mismatched env across functions can seed the wrong policy. After the row exists, live policy comes from DynamoDB (and from `PUT /config/policy`), not from these env vars.

**Shared placeholders**

| Placeholder | Description |
|-------------|-------------|
| `YOUR_DYNAMODB_TABLE` | DynamoDB table name (`pk` + `sk` keys) |
| `YOUR_TENANT_ID` | Microsoft Entra tenant (directory) ID |
| `YOUR_AUDIENCE` | Expected JWT `aud` (e.g. `api://...` or app ID URI) |
| `YOUR_API_BASE` | API Gateway base URL, **no trailing slash** (include stage if used, e.g. `https://xxx.execute-api.us-east-1.amazonaws.com/prod`) |
| `YOUR_CONFIG_TOKEN` | Strong random secret; client sends `x-config-token` |
| `YOUR_DEV_BEARER` | Optional static bearer when using insecure dev auth |

---

## 1. `validate` (`validate.zip` — `POST /validate`)

**Production (Entra JWT)**

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
ENTRA_TENANT_ID=YOUR_TENANT_ID
ENTRA_AUDIENCE=YOUR_AUDIENCE
JWT_CLOCK_SKEW_SECONDS=60
JWKS_CACHE_TTL_MS=300000
```

Optional: `ENTRA_ISSUER`, `ENTRA_JWKS_URI`.

**Development only (not for production Copilot)**

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
ALLOW_INSECURE_LOCAL_AUTH=true
AUTH_TOKEN=YOUR_DEV_BEARER
```

---

## 2. `analyze-tool-execution` (`analyze-tool-execution.zip` — `POST /analyze-tool-execution`)

**Production**

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
ENTRA_TENANT_ID=YOUR_TENANT_ID
ENTRA_AUDIENCE=YOUR_AUDIENCE
JWT_CLOCK_SKEW_SECONDS=60
JWKS_CACHE_TTL_MS=300000
BLOCKED_TERMS=wire transfer,secret key,exfiltrate
BLOCKED_TOOL_NAMES=Delete record
```

**Development only**

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
ALLOW_INSECURE_LOCAL_AUTH=true
AUTH_TOKEN=YOUR_DEV_BEARER
BLOCKED_TERMS=wire transfer,secret key,exfiltrate
BLOCKED_TOOL_NAMES=Delete record
```

`BLOCKED_*` seed the policy row when `APP` / `POLICY` does not exist yet.

**Copilot topics.** Copilot Studio topics are exposed to the planner as pseudo-tools and
trigger this webhook (even when disabled in the agent), identified by `.topic.` in the
`toolDefinition.id`. By default they are **allowed without a PDP call** so they don't
produce duplicate or blank-named decision-log entries. Set `EVALUATE_COPILOT_TOPICS=true`
to send them to the PDP like real (`.action.`) tools.

**Reva PDP (optional).** When all three of `REVA_PDP_URL`, `REVA_POLICY_STORE_ID`, and
`REVA_PDP_TOKEN` are set, the allow/block decision is delegated to the Reva Evaluation API
instead of the local `BLOCKED_*` policy. The `BLOCKED_*` lists still run — but only to
*compute* the guardrail flags that travel to the PDP as context, not to decide.

```text
REVA_PDP_URL=https://api.<your-env>.reva.ai/pdp/v2/ai/evaluation
REVA_POLICY_STORE_ID=YOUR_POLICY_STORE_UUID
REVA_PDP_TOKEN=YOUR_PDP_BEARER_TOKEN
REVA_PDP_ORIGIN=https://<your-console>.reva.ai   # optional: Origin header for the Reva gateway
REVA_PDP_SURFACE_RESPONSE=true                 # optional: surface the PDP's context.reason
```

`REVA_PDP_URL` must be the **full** Evaluation API URL ending in `/pdp/v2/ai/evaluation`.

> **Moving from v1 to v2 needs a NEW token.** A credential that answers `200` on
> `/pdp/access/v1/ai/evaluation` answers `401` on `/pdp/v2/ai/evaluation`. The failure
> presents as an auth problem, not a version problem, so it is easy to misread. The service
> reports this as `errorKind: "auth"` rather than as a policy block.

### Observability data: closed by default

```text
CONFIG_API_TOKEN=<strong random secret>   # required to read observability data
OBS_STORE_PROMPTS=false                   # default false — do not retain conversation text
```

The observability store holds one record per authorization decision. Unredacted that is the
user's own words, the planner's reasoning about them, whatever the tools returned, the call's
arguments, the user's Entra object id and their IP address — served back over plain HTTP GETs.

Two changes make that safe by default:

**The data routes require `x-config-token`.** `GET /observability/events`,
`DELETE /observability/events` and `GET /observability/policy` all refuse without it, and are
**disabled entirely** when `CONFIG_API_TOKEN` is unset. Forgetting to configure a token gives
you a dark dashboard, not an open one. `GET /observability` — the page itself — stays open
because a browser cannot set a header on a navigation; it carries no data and prompts for the
token, holding it in the tab only.

**Conversation content is not retained.** Prompts, planner thoughts, chat history, tool output
values, argument values and the client IP are replaced with `[redacted]` on the way *in*, so
data that was never written cannot leak from a route someone forgot to protect, cannot be read
by whoever has database access, and is not in a backup. Ids, tool names, structure, counts,
timings and decisions all survive, which is what a diagnosis is actually made of.

`OBS_STORE_PROMPTS=true` retains the content for a debugging session. Treat it as a temporary
setting on a store holding personal data.

### Enforcement mode

```text
REVA_MODE=enforce            # enforce (default) | monitor | log
```

`monitor` (`log` is a synonym) evaluates for real, records the verdict, and lets the call
through anyway. It is how a rollout starts: run production Copilot traffic against real
policy, read what **would** have been refused, then switch to `enforce`. The would-be denial
is written to the observability event as `monitorWouldDeny`, carrying the PDP's own reason —
not the generic "Blocked by Reva authorization policy", because a monitor run that cannot say
*why* is not worth doing. The event's `response` still reads as allowed, which is what
happened, so the verdict is recorded separately rather than inferred from a passing event.

Spelling matches the LiteLLM (`REVA_HOOK_MODE`) and TrueFoundry (`mode`) plugins.

Monitor mode governs only a decision the PDP actually gave. A **fault** — unreachable, timed
out, rejected our body — still fails closed under `REVA_FAIL_OPEN`. The two are deliberately
separate: otherwise you could not watch policy without also disarming the outage path.

### Reliability

```text
REVA_PDP_TIMEOUT_MS=2500     # default 2500, shared by BOTH attempts
REVA_FAIL_OPEN=false         # default false (fail CLOSED)
```

A connection that dies mid-flight (`ECONNRESET`, `EPIPE`, `ECONNABORTED`, `UND_ERR_SOCKET`)
is retried **once**. A pooled socket the peer closed while we were idle fails instantly and
succeeds on a second try, and on a fail-closed path that failure blocks a legitimate tool
call. Nothing else is retried: a timeout has already spent the budget, and a refused
connection or failed DNS means the service is down, where retrying only delays an answer we
already have.

`REVA_PDP_TIMEOUT_MS` is **one deadline for the whole operation**, not one per attempt —
Microsoft fails open past its own ~1 s budget, so a retry that restarted the clock could let
Copilot proceed unauthorized while we were still asking. The event records `attempts` and,
when a retry happened, `retriedAfter` with the socket error code.

Microsoft expects a decision in about **one second** and **fails open** on its own timeout,
so a service that simply hangs silently allows the tool call. Reva measured 2.6-3.0s with
guardrails in ENFORCE mode, so this bound is a real policy choice: too tight denies work the
PDP was about to allow, too loose lets Copilot proceed before we answer.

On timeout or an unreachable PDP the service answers Microsoft with **HTTP 200 and
`blockAction: true`** (`reasonCode` **103**), not a 5xx. Returning a 5xx would hand the
decision to the Power Platform *error behavior* setting, whose default is to allow. The
reason text names a **service** failure rather than a policy one, because "blocked by
policy" sends the reader into Cedar and "could not reach the authorization service" sends
them to their configuration. `REVA_FAIL_OPEN=true` inverts this and is for debugging only.

Which failure it was is on the observability event as `errorKind`, and each value points at a
different place to look:

| `errorKind` | Meaning |
|---|---|
| `transport` | the PDP was never reached |
| `timeout` | reached, no answer inside `REVA_PDP_TIMEOUT_MS` |
| `auth` | `401` — usually a v1 token against the v2 endpoint |
| `no-principal` | refused here, before the call: the end user was not in the body (see *Who the principal is*) |
| `invalid-payload` | the PDP answered and **rejected the body we sent** — a bug on this side, not a policy decision. Its own reason is on the event |

`invalid-payload` exists because **a `decision:false` body is not proof of a decision.** The
API answers a rejected *payload* the same way it answers a denied *request*. Probed on pr06,
2026-09-10:

| what happened | HTTP | `error_type` | is it a decision? |
|---|---|---|---|
| Cedar denied the request | 403 | **`POLICY_DENIED`** | **yes** |
| resource type the action does not take | 403 | *absent* | no — our payload is wrong |
| action the resource does not take | 403 | *absent* | no |
| malformed `session` or `context` | 400 | *absent* | no |

So `error_type: "POLICY_DENIED"` is the only positive signal that a `403` is a verdict, and
it is what the service keys on. Treating every `403` as a deny reported our own bad request
to Copilot as `reasonCode` **101**, "Blocked by Reva authorization policy" — which sends
whoever debugs it into Cedar hunting a rule that does not exist.

> `error_type` is undocumented, so it may change. If it ever stops appearing, real denials
> degrade to `invalid-payload`: still blocked, still fail-closed, `reasonCode` 103 instead of
> 101, and the event still carries the PDP's own `authorization denied by policy`. A wrong
> label, never a wrong decision — the safe direction to be wrong in.

### Who may call this webhook

```text
ENTRA_ALLOWED_APP_IDS=<caller app GUID>[,<another>]   # default empty (unenforced)
```

Validating the token proves it came from the right **tenant** for the right **audience**. It
does not prove *Power Platform* sent it. Without this list, any application in the customer's
tenant that can obtain a token for your audience can drive the webhook — and this webhook
decides whether tool calls are authorized.

Microsoft makes this the partner's responsibility rather than the platform's:

> "you need to implement authorization logic and validate incoming tokens … for example,
> using an allow list of app IDs, or role-based access control"
> — [Build a runtime threat detection system for Copilot Studio agents](https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers)

**Finding the value.** It is the **Azure Entra App ID** registered during setup and entered in
Power Platform admin center under *Security → Threat detection*. Each customer registers their
own application, so this is a per-deployment value, not a Microsoft constant — Power Platform
federates into that app, so the `appid`/`azp` claim we receive is exactly that App ID.

Every observability event also records `callerAppId` from the verified token, so you can
confirm the two match before switching enforcement on.

It is left empty by default because shipping a guessed GUID as a security control is worse
than shipping none — but leaving it empty in production means the control is off.

This is the same model Microsoft Defender uses as a provider; their troubleshooting documents
the rejection as *"The application ID in your authentication token doesn't match the registered
application for webhook access."*

Once set, a valid same-tenant token from any other application is rejected, and a token with
no `appid`/`azp` is rejected too: being unable to identify the caller is not the same as the
caller being permitted.

### Who the principal is

```text
REVA_REQUIRE_BODY_PRINCIPAL=false   # default false
```

The principal is the originating **end user**. It comes from `conversationMetadata.user.id`
in Microsoft's body — deliberately in preference to the verified bearer token, which looks
backwards and is not. That token authenticates *Power Platform* calling us, and under the
federated credential of INSTALL.md §4.2 it is an app identity: its `oid` is a service
principal, not the person who typed. Preferring it would substitute "Power Platform" for a
real user and authorize the wrong subject. The token's claims are a last resort, kept only
for a delegated test token.

Which source answered is on every event as the first half of `entityResolution.user`, e.g.
`conversation-metadata:id-map` or `token-oid:passthrough`. Anything other than
`conversation-metadata` means the end user was absent from the payload — the request will
look entirely healthy while authorizing the wrong subject, so it is worth alerting on.

Set `REVA_REQUIRE_BODY_PRINCIPAL=true` to refuse those outright, before the PDP call, with
`errorKind: "no-principal"`.

### Entity mapping

Microsoft and Reva share no identifier space. Microsoft sends Entra and Dataverse GUIDs and
Power Platform component ids; Reva uses topology slugs. Three maps bridge them, each JSON:

```text
REVA_PRINCIPAL_ID_MAP={"22222222-2222-2222-2222-222222222222":"alice"}
REVA_AGENT_ID_MAP={"33333333-3333-3333-3333-333333333333":"underwriter-copilot"}
REVA_TOOL_ID_MAP={"pub_UnderwriterCopilot.action.UnderwriterCopilotTools-UnderwriterCopilotTools_nAl":"send-notification-email"}
```

Resolution per entity is **id map -> name map -> slug of the display name**, and which rung
answered is reported on every event as `entityResolution`.

**Mapping is optional.** Entity **ids are free-form** — nothing has to exist in the store
before you name it. Verified against pr06 on 2026-09-10: a request carrying raw Entra and
Dataverse GUIDs that were never ingested is evaluated normally. What the API *does* check is
the entity **type** and the **action**, both of which come from the schema:

```text
resource {type:"Widget"}  ->  403 invokeTool requires a Tool resource, resolved "Widget"
action   "frobnicate"     ->  403 Tool resource requires action invokeTool
```

This changed with the policy store, not the API. A store built on **named-entity** policies
auto-permits each connected edge, so an entity with no edge had no permit and was denied by
omission — you genuinely had to ingest it first. A store written with **open** policies
("any Agent may invoke this Tool when …") matches on type and condition, so an unregistered
id is ordinary traffic.

> **`REVA_ON_UNMAPPED_ENTITY` has been removed.** It refused a request whose agent or tool
> resolved only by slug, on the premise that an unregistered id comes back as
> `403 authorization denied by policy`. pr06 answers `200` and evaluates it, so the flag was
> blocking calls the PDP would have allowed. Setting it now does nothing.

What the maps still buy is **readability and named-policy compatibility**: a decision log
reading `underwriter-copilot` is worth more than `33333333-3333-3333-3333-333333333333`, and
a store that does name its entities still needs the ids to line up. Note the slug fallback is
coupled to the Copilot Studio *display name*, so a rename silently changes the resolved id —
which matters only for a store in that second category. `toolDefinition.id` cannot be
slugified at all: its trailing `_nAl` / `_ctk` is a Power Platform-generated token, unrelated
to the tool name and unstable across solution re-imports.

### Writing open policies

A named-entity policy asks *"is this `amit` calling `fetch-risk-score`?"* and needs both
registered. An **open** policy asks *"may any agent call this tool, in these
circumstances?"* — which only works if the circumstances are in the payload. Two mechanisms
carry them.

#### The two kinds of context attribute

This distinction decides whether your policy fires, so it is worth getting right.

| | Named by | Prefixed? |
|---|---|---|
| **The schema's own** — `timestamp`, `sourceIp`, `environment`, `onBehalfOf`, `chain`… | the platform | **no** — the declared name is the name |
| **Yours** — anything you add to the store | you | **yes** — `<StoreName>_<attr>` |

Prefixing a schema attribute invents a key nobody declared *and* leaves the declared one
missing, so it fails twice. `REVA_CONTEXT_ATTR_PREFIX` therefore applies only to the second
row.

**Does the plugin need to know every attribute in your schema? No.** It needs the prefix,
and nothing else. Attributes the schema does not declare are accepted and ignored (verified
on pr06, 2026-09-10), so the plugin can send a superset; the schema only decides what a
policy may be *written* against. The coupling runs the other way: an attribute the plugin
does **not** send is a policy that silently never fires, so treat the list below as the
contract and declare what you intend to use.

> `required: true` in the schema is enforced when **ingesting entity data**, not when
> evaluating. The PDP evaluates whatever arrives, and a policy fires if the attributes it
> names are present. That is why `chain` — declared required, yet rejected by this API as a
> record — is survivable rather than fatal.

**1. Schema-declared attributes** (on by default, no prefix):

```text
REVA_SEND_SCHEMA_CONTEXT=true    # default true
REVA_ENVIRONMENT_MAP={"55555555-5555-5555-5555-555555555555":"PROD"}
```

| context key | type | from |
|---|---|---|
| `timestamp` | Long | request time in **milliseconds** — the schema does not state a unit, so a policy comparing it must agree |
| `sourceIp` | String | `conversationMetadata.incomingClientIp` |
| `environment` | String enum `PROD \| STAGING \| DEV \| SANDBOX` | `REVA_ENVIRONMENT_MAP` keyed by the Copilot environment GUID; unmapped means not sent |

`environment` is where v1 went wrong: it sent a **Record** (`{requestId, time, sourceIp,
traceparent}`) into a key the schema declares as one of four strings, so no policy could ever
have matched it. The key was fine; the shape was not.

**2. Copilot metadata as custom attributes** (on by default, **prefixed**):

```text
REVA_SEND_COPILOT_CONTEXT=true   # default true
```

| context key | from | example |
|---|---|---|
| `tenantId` | `conversationMetadata.user.tenantId` | `74fd0612-…` |
| `channelId` | `conversationMetadata.channelId` | `pva-studio` |
| `agentEnvironmentId` | `conversationMetadata.agent.environmentId` | `55555555-…` |
| `agentIsPublished` | `conversationMetadata.agent.isPublished` | `false` |
| `copilotToolType` | `toolDefinition.type` | `CustomConnectorToolDefinition` |

```
permit(...) when { context.MyStore_agentIsPublished == true };   // no draft agents
forbid(...) when { context.MyStore_channelId == "pva-studio" };  // not from the editor
```

It is `copilotToolType`, not `toolType`, on purpose: the schema already has `Tool.toolType` as
an **entity** attribute whose values are `MCP | OPENAPI | FUNCTION | …`. Microsoft's is a
different concept with a disjoint value space, and one name for two of those is a trap for
whoever writes the policy.

Nothing here is prompt text: ids, a channel name and a boolean.

**2. Group membership as Cedar entity data:**

```text
REVA_USER_GROUPS_MAP={"22222222-2222-2222-2222-222222222222":["Underwriters","EndUser"]}
```

This emits an `entities` block declaring the user's `UserGroup` parents **with the request**,
so a policy can say `principal in UserGroup::"Underwriters"` without the user being
registered in the store:

```json
"entities": [{ "uid": {"type":"User","id":"91e2d18d-…"},
               "parents": [{"type":"UserGroup","id":"Underwriters"}] }]
```

The Kong plugin does the same thing but reads the groups off a JWT claim. That is not
available here: the bearer token on this webhook authenticates Power Platform, not the
person, and carries no claims about them — so the source has to be configuration. Key it by
the raw Entra GUID or by the resolved Reva id; both are checked.

Unset means no `entities` key at all and a payload byte-identical to before. Note only the
**User** is declared: entity *attributes* were accepted in testing, but unlike ids they are
schema-defined, and an attribute the schema does not know is a silent drop.

### Payload shaping

```text
REVA_CONTEXT_ATTR_PREFIX=       # default empty
REVA_INCLUDE_PLANNER_THOUGHT=true
REVA_SESSION_MAX_TURNS=10
REVA_SESSION_MAX_CHARS=2000
```

`REVA_CONTEXT_ATTR_PREFIX` namespaces the attributes you added to the store — spaces and
underscores stripped, casing kept, `_` appended, so `My_Policy_Store` becomes
`MyPolicyStore_`. **Cedar matches context keys by exact name and a missing key is not
an error** — it fails the `has` guard, so a wrong prefix means the policy publishes and
never fires. Verify against your store's decision log before writing policies against it.

> **The four blocked-term flags (`blockedTermInUserMessage`, `blockedTermInInput`,
> `isBlockedTool`, `blockedTermInPreviousOutput`) are no longer sent.** No policy referenced
> them and they were never declared in the schema. `BLOCKED_TERMS` / `BLOCKED_TOOL_NAMES`
> still do two jobs: they enforce locally on the no-PDP fallback path, and the flags are
> still computed and recorded on the observability event, so "this request contained a
> blocked term" stays visible. `REVA_SEND_CONTEXT_FLAGS` is gone; setting it does nothing.

`REVA_SESSION_MAX_*` bound the prior-turn history. The PDP rejects a body over 1,048,576
bytes *before* authorization, so an uncapped chat degrades into hard failures gradually as
the conversation grows. The service trims progressively (tool arguments, then responses,
then history, then — last — the hop chain itself) and reports what it dropped as
`trimSteps` on the observability event. It never fails a request on size.

### What the request looks like

The Lambda POSTs one JSON object —
`subject` / `action` / `resource` / `principal` / `context` / `transmission` / `inputValues` / `session` —
and reads `{ "decision": true }` (allow) or `{ "decision": false, "context": { "reason": … } }` (deny).
A non-2xx that still carries a `decision` is treated as a decision: a `403` deny is a block,
not a transport failure.

Three details in that body are load-bearing for guardrail detection, and each was wrong on v1:

- **`context` carries `conversation` and `hops` and nothing else of our own.** Records are
  allowed only from a fixed allowlist; anything outside it fails the whole request, naming
  the key: `400 invalid Cedar context: managed context records are not supported at managed
  context.<key>`. Probed one key at a time against pr06 on 2026-09-10:

  | key | result |
  |---|---|
  | `conversation`, `hops`, `chatHistory` | accepted |
  | `environment`, `onBehalfOf` | **accepted — both are on the allowlist** |
  | `chain`, or any other record | `400` |
  | flat scalars, scalar arrays | accepted |

  We send neither `environment` nor `onBehalfOf`, but because they are **inert, not fatal**:
  `onBehalfOf` is projected server-side from `principal` and shows up in the decision log
  without us sending it, trace context travels in the `traceparent` header, and `environment`
  is not usable in a policy on this platform anyway. An earlier revision of this file claimed
  sending them "would have denied every call on v2" — that is not what the API does.
- **`transmission.role` is `agent`,** matching `subject.type`. A user instruction is
  authoritative — it *sets* intent rather than being measured against it — so labelling the
  agent's own decision `user` makes `ALIGNED` the correct verdict however far the agent has
  wandered.
- **`transmission.content` describes the hop,** not the user's message. Sending the user's
  prompt makes the payload agree with itself, and a hop compared against itself can never
  drift.

`context.conversation` and `context.hops` are the same turn counted two ways and always
carry the same number of entries; a divergence is a defect. The counts appear on every
observability event as `payloadShape`.

A fourth detail is load-bearing on the way in: **every entry in `session.messages` must carry
a non-empty `response.content`.** The PDP validates this before authorizing and refuses the
whole request over one bad entry — omitting the key answers
`400 invalid session: session.messages[0].response is required`, and an empty string answers
`…response.content is required` (both verified against pr06 on 2026-09-10). Copilot produces
an unanswerable turn routinely: an assistant turn that is a bare tool call has no text, so the
user turn before it never closes. Those turns are therefore **dropped** before sending. That
costs one turn of history and leaves a gap in the turn numbering, which the PDP accepts —
sending them costs every remaining call in that chat. `session.turn` stays absolute and does
not shift down, because the dropped turn did happen; we just cannot describe it.

---

## 3. `observability` (`observability.zip` — `GET /observability`)

This function does not call DynamoDB at runtime.

```text
OBS_MAX_EVENTS=200
PUBLIC_API_BASE=YOUR_API_BASE
```

`PUBLIC_API_BASE` is optional if the browser loads the dashboard from the same origin and relative paths `/observability/events` and `/observability/policy` resolve correctly.

---

## 4. `observability-events-list` (`observability-events-list.zip` — `GET /observability/events`)

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
OBS_MAX_EVENTS=200
```

---

## 5. `observability-events-clear` (`observability-events-clear.zip` — `DELETE /observability/events`)

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
```

---

## 6. `observability-policy` (`observability-policy.zip` — `GET /observability/policy`)

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
BLOCKED_TERMS=wire transfer,secret key,exfiltrate
BLOCKED_TOOL_NAMES=Delete record
```

Optional (same value as config Lambdas if you want `configApiEnabled: true` in the JSON):

```text
CONFIG_API_TOKEN=YOUR_CONFIG_TOKEN
```

---

## 7. `observability-otel-export` (`observability-otel-export.zip` — `POST /observability/otel-export`)

On-demand export: queries the Reva decision-log API (server-side credentials), converts each returned row to an OTLP log, and **POST**s to your OpenTelemetry Collector’s OTLP HTTP endpoint. The collector **hosting** code lives in **[`Utils/otel-collector/`](../../Utils/otel-collector/)** (out of the Lambda package). Does **not** call DynamoDB. Does **not** change the Copilot webhook flow.

**Auth:** same `x-config-token` header as `config/policy` (must match `CONFIG_API_TOKEN`). The observability page prompts for this token when you click **Send to Datadog (OTEL)**.

```text
CONFIG_API_TOKEN=YOUR_CONFIG_TOKEN
REVA_DECISION_LOG_QUERY_URL=https://api.example.reva.ai/api/v1/logs/decision/query
OTEL_COLLECTOR_OTLP_HTTP_URL=http://otel-collector.internal:4318/v1/logs
```

Optional override for the JSON body sent to Reva (otherwise a default filter is used):

```text
REVA_DECISION_LOG_BODY_JSON={"filters":[{"field":"application_name","operator":"is_not","value":"Reva"}]}
```

Also configure the Collector with **`DD_API_KEY`** (see [`Utils/otel-collector/README.md`](../../Utils/otel-collector/README.md)). For **EU** Datadog, uncomment `api.site` in [`Utils/otel-collector/config.yaml`](../../Utils/otel-collector/config.yaml) or [`config.render.yaml`](../../Utils/otel-collector/config.render.yaml).

`POST` handler returns **`OPTIONS`** `204` with CORS headers for browser preflight when API Gateway allows it.

---

## 8. `config-policy-read` (`config-policy-read.zip` — `GET /config/policy`)

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
CONFIG_API_TOKEN=YOUR_CONFIG_TOKEN
BLOCKED_TERMS=wire transfer,secret key,exfiltrate
BLOCKED_TOOL_NAMES=Delete record
```

---

## 9. `config-policy-write` (`config-policy-write.zip` — `PUT /config/policy`)

```text
DYNAMODB_TABLE_NAME=YOUR_DYNAMODB_TABLE
CONFIG_API_TOKEN=YOUR_CONFIG_TOKEN
BLOCKED_TERMS=wire transfer,secret key,exfiltrate
BLOCKED_TOOL_NAMES=Delete record
```

Use the **same** `CONFIG_API_TOKEN` on **config-policy-read**, **config-policy-write**, **observability-otel-export**, and optionally **observability-policy**.

---

## Variable reference

| Variable | Used on |
|----------|---------|
| `DYNAMODB_TABLE_NAME` | All except `observability`, `observability-otel-export` |
| `ENTRA_TENANT_ID`, `ENTRA_AUDIENCE` | `validate`, `analyze-tool-execution` (production) |
| `ENTRA_ISSUER`, `ENTRA_JWKS_URI` | Optional on webhook Lambdas |
| `JWT_CLOCK_SKEW_SECONDS`, `JWKS_CACHE_TTL_MS` | Optional on webhook Lambdas |
| `ALLOW_INSECURE_LOCAL_AUTH`, `AUTH_TOKEN` | `validate`, `analyze-tool-execution` (dev only) |
| `BLOCKED_TERMS`, `BLOCKED_TOOL_NAMES` | `analyze-tool-execution`, `observability-policy`, `config-policy-read`, `config-policy-write` |
| `OBS_MAX_EVENTS` | `observability`, `observability-events-list` |
| `PUBLIC_API_BASE` | `observability` |
| `CONFIG_API_TOKEN` | `config-policy-read`, `config-policy-write`, `observability-otel-export`; optional on `observability-policy` |
| `REVA_DECISION_LOG_QUERY_URL`, `OTEL_COLLECTOR_OTLP_HTTP_URL`, `REVA_DECISION_LOG_BODY_JSON` (optional) | `observability-otel-export` |
