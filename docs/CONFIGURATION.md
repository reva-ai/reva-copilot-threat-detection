# Configuration

Everything is an environment variable. This page lists all of them, grouped by what they
are for, with the defaults the code actually applies.

**The short version.** Six variables make a working, secure deployment:

```bash
ENTRA_TENANT_ID=<your tenant GUID>
ENTRA_AUDIENCE=https://threatdetection.yourcompany.com
ENTRA_ALLOWED_APP_IDS=<the Application (client) ID from setup>
REVA_PDP_URL=https://api.<your-env>.reva.ai/pdp/v2/ai/evaluation
REVA_POLICY_STORE_ID=<policy store id>
REVA_PDP_TOKEN=<v2 API token>
```

Everything else has a default that is right for most deployments. Prefer leaving a variable
unset over setting it to its default — an unset variable cannot drift.

---

## Identity: who may call this service

```bash
ENTRA_TENANT_ID=11111111-1111-1111-1111-111111111111     # required
ENTRA_AUDIENCE=https://threatdetection.yourcompany.com   # required
ENTRA_ALLOWED_APP_IDS=77777777-7777-7777-7777-777777777777
ENTRA_ISSUER=                                            # optional override
ENTRA_JWKS_URI=                                          # optional override
JWT_CLOCK_SKEW_SECONDS=60
JWKS_CACHE_TTL_MS=300000
```

`ENTRA_AUDIENCE` must be **byte-identical** to the Application ID URI on your app
registration. This is the most common misconfiguration; a mismatch produces `AADSTS500011`.

**`ENTRA_ALLOWED_APP_IDS` is the one not to skip.** Validating a token proves it came from
the right tenant for the right audience. It does **not** prove Copilot Studio sent it — any
application in your tenant able to obtain a token for your audience passes. This pins the
caller.

The value is the **Application (client) ID** you registered during setup and entered in
Power Platform admin center. Power Platform federates into that app, so the `appid` (v1) or
`azp` (v2) claim on every incoming token equals it. Not a discovery exercise: it is on the
app registration's overview page.

Microsoft treats this as the provider's responsibility, and their own Defender integration
enforces the same check. Unset, the control is off — the code ships that way because the
correct value is specific to your tenant.

Comma-separate several. Comparison is case-insensitive. Once set, a token carrying no
`appid`/`azp` claim is also refused: being unable to identify the caller is not the same as
the caller being permitted.

### Local development only

```bash
ALLOW_INSECURE_LOCAL_AUTH=true
AUTH_TOKEN=some-dev-token        # optional; omit for no auth at all
```

Replaces Entra validation with a static token, or with nothing. The service **refuses to
start** unless either these or `ENTRA_TENANT_ID` + `ENTRA_AUDIENCE` are present, so there is
no way to accidentally run it unauthenticated. Never set this outside a laptop.

---

## The Reva PDP: where decisions come from

```bash
REVA_PDP_URL=https://api.<your-env>.reva.ai/pdp/v2/ai/evaluation   # required
REVA_POLICY_STORE_ID=<policy store id>                             # required
REVA_PDP_TOKEN=<v2 API token>                                      # required
REVA_PDP_ORIGIN=https://<your-console>.reva.ai                     # if your tenant needs it
REVA_PDP_SURFACE_RESPONSE=false
```

All three required values must be present, or the service silently falls back to the local
`BLOCKED_*` word list instead of asking the PDP — which looks like the PDP allowing
everything.

The URL must be the **full** endpoint ending `/pdp/v2/ai/evaluation`, with a **v2** token: a
token issued for `/pdp/access/v1/…` returns `401` on v2. That failure presents as an
authentication problem rather than a version problem, so the service reports it as
`errorKind: "auth"` and never as a policy block.

`REVA_PDP_SURFACE_RESPONSE=true` passes the PDP's own reason text through to Copilot. Useful
while tuning policy; consider whether you want policy detail visible to end users.

### Enforcement mode

```bash
REVA_MODE=enforce        # enforce (default) | monitor | log
```

`monitor` (and its synonym `log`) evaluates for real, records the verdict, and lets the call
through regardless. **Start here.** Your policies have never met your real traffic, and this
is how you learn what they would refuse before anyone is blocked by a mistake.

Each would-be denial is written to the observability event as `monitorWouldDeny`, carrying
the PDP's own reason rather than the generic "blocked by policy" text — a monitor run that
cannot say *why* is not worth doing.

Monitor governs a decision the PDP **gave**. A fault — unreachable, timed out, request
rejected — still fails closed under `REVA_FAIL_OPEN`. The two are deliberately separate:
otherwise you could not watch policy without also disarming the outage path.

### Reliability

```bash
REVA_PDP_TIMEOUT_MS=2500     # one deadline shared by BOTH attempts
REVA_FAIL_OPEN=false         # debug only
```

A connection that dies mid-flight (`ECONNRESET`, `EPIPE`, `ECONNABORTED`, `UND_ERR_SOCKET`)
is retried **once**. A pooled socket the peer closed while idle fails instantly and succeeds
on a second try, and on a fail-closed path that failure blocks a legitimate tool call.
Nothing else is retried: a timeout has already spent the budget, and a refused connection or
failed DNS means the service is down, where retrying only delays an answer you already have.

> ### The latency budget you cannot configure your way out of
>
> Microsoft allows this webhook about **1000 ms** and, past that, proceeds as though the
> answer were *allow*. That is Microsoft's behaviour; no setting here overrides it.
>
> There is no correct timeout value. Set it below the budget and a healthy-but-slow PDP is
> cut off and — failing closed — blocks legitimate calls. Set it above and Copilot has
> already given up before you answer.
>
> So measure rather than assume. Every event carries the handler's end-to-end latency and
> `budgetExceeded`. **A sustained run of `budgetExceeded: true` means you are not enforcing**,
> whatever your policies say. If you see that, the conversation is about PDP latency, not
> about this variable.

### Failure diagnosis

When no decision can be obtained, the response to Copilot is `blockAction: true` with reason
code **103**, and wording naming a *service* failure — never "blocked by policy", which
would send whoever debugs it into Cedar hunting a rule that does not exist.

The observability event carries `errorKind`, and each value points somewhere different:

| `errorKind` | Meaning |
|---|---|
| `transport` | the PDP was never reached |
| `timeout` | reached, no answer within the budget |
| `auth` | `401` — usually a v1 token against the v2 endpoint |
| `invalid-payload` | the PDP answered and **rejected what we sent** — a bug on this side |
| `no-principal` | refused here, before the call: the end user was absent from the body |

`invalid-payload` exists because a `decision:false` body is not proof of a decision. The API
answers a rejected *payload* the same way it answers a denied *request*, and only
`error_type: "POLICY_DENIED"` distinguishes them.

---

## What the policy can decide on

### Identity mapping (optional)

```bash
REVA_PRINCIPAL_ID_MAP={"<entra-user-guid>":"alice"}
REVA_AGENT_ID_MAP={"<copilot-agent-guid>":"underwriter-copilot"}
REVA_TOOL_ID_MAP={"<full toolDefinition.id>":"send-notification-email"}
```

**Entity ids are free-form.** The PDP evaluates ids that exist nowhere in your store — what
it checks is the entity *type* and the *action*, which come from the schema. So whether you
need these depends on how your policies are written:

| Policy style | Maps |
|---|---|
| **Open** — "any Agent may invoke this Tool when …" | not required |
| **Named-entity** — "`underwriter-copilot` may call `fetch-risk-score`" | required |

Resolution is **id map → name map → slug of the display name**, and which rung answered is
recorded on every event as `entityResolution`. Agents and tools already slug to readable
values from their display names, so in practice only `REVA_PRINCIPAL_ID_MAP` meaningfully
improves a decision log — without it the user stays a raw GUID.

`toolDefinition.id` cannot be slugified: its trailing `_nAl`/`_ctk` is a Power
Platform-generated token, unrelated to the tool name and unstable across solution re-imports.

### Group membership

```bash
REVA_USER_GROUPS_MAP={"<entra-user-guid>":["Underwriters","EndUser"]}
```

Emits a Cedar `entities` block declaring the user's `UserGroup` parents **with the request**,
so a policy can say `principal in Identity::UserGroup::"Underwriters"` without the user
existing in the store.

The source has to be configuration: the bearer token on this webhook authenticates Power
Platform, not the person, and carries no claims about them. Key by the raw Entra GUID or by
the mapped id — both are checked. Unset means no `entities` key at all.

### Context attributes

Two kinds, and the distinction decides whether your policy fires:

| | Named by | Prefixed? |
|---|---|---|
| **The schema's own** — `timestamp`, `sourceIp`, `environment` | the platform | **no** |
| **Yours** — anything you add to the store | you | **yes**, `<StoreName>_` |

Prefixing a schema attribute invents a key nobody declared *and* leaves the declared one
missing, so it fails twice.

```bash
REVA_SEND_SCHEMA_CONTEXT=true    # timestamp, sourceIp, environment
REVA_SEND_COPILOT_CONTEXT=true   # the prefixed set below
REVA_CONTEXT_ATTR_PREFIX=        # e.g. MyPolicyStore_
REVA_ENVIRONMENT_MAP={"<copilot-env-guid>":"PROD"}
```

Schema-declared, sent **unprefixed**:

| Key | Type | Source |
|---|---|---|
| `timestamp` | Long | request time in **milliseconds** — a policy comparing it must agree on the unit |
| `sourceIp` | String | `conversationMetadata.incomingClientIp` |
| `environment` | `PROD \| STAGING \| DEV \| SANDBOX` | via `REVA_ENVIRONMENT_MAP`; unmapped means not sent |

Copilot metadata, sent **prefixed**:

| Key | Source | Example |
|---|---|---|
| `tenantId` | `conversationMetadata.user.tenantId` | `11111111-…` |
| `channelId` | `conversationMetadata.channelId` | `pva-studio` |
| `agentEnvironmentId` | `conversationMetadata.agent.environmentId` | `55555555-…` |
| `agentIsPublished` | `conversationMetadata.agent.isPublished` | `false` |
| `copilotToolType` | `toolDefinition.type` | `CustomConnectorToolDefinition` |

```
permit(...) when { context.MyPolicyStore_agentIsPublished == true };   // no draft agents
forbid(...) when { context.MyPolicyStore_channelId == "pva-studio" };  // not from the editor
```

It is `copilotToolType`, not `toolType`, deliberately: the Reva schema already has
`Tool.toolType` as an *entity* attribute with values `MCP | OPENAPI | FUNCTION | …`.
Microsoft's is a different concept with a disjoint value space, and one name over two of
those is a trap for whoever writes the policy.

**Attributes the schema does not declare are accepted and ignored**, so sending a superset
is safe. The coupling runs the other way: an attribute this service does *not* send is a
policy that silently never fires.

### Payload shaping

```bash
REVA_INCLUDE_PLANNER_THOUGHT=true
REVA_SESSION_MAX_TURNS=10
REVA_SESSION_MAX_CHARS=2000
REVA_REQUIRE_BODY_PRINCIPAL=false
```

`REVA_SESSION_MAX_*` bound the prior-turn history. The PDP rejects a body over 1 MiB
*before* authorizing, so an uncapped chat would degrade into hard failures gradually as the
conversation grows. The service trims progressively — tool arguments, then responses, then
history, then the hop chain — and records what it dropped as `trimSteps`. It never fails a
request on size.

`REVA_REQUIRE_BODY_PRINCIPAL=true` refuses when the end user is absent from
`conversationMetadata`, rather than falling back to the transport identity — which, under
the production federated credential, is Power Platform's service principal and not a person.

---

## Local word-list policy

```bash
BLOCKED_TERMS=wire transfer,secret key,exfiltrate
BLOCKED_TOOL_NAMES=Delete record
```

A fallback, used **only** when the PDP is not configured. With a PDP configured these do not
decide anything. They seed the stored policy row on first use; after that the live value
comes from the store, and from `PUT /config/policy` if you enable it.

---

## Storage

```bash
STORAGE_BACKEND=memory        # memory (default) | dynamodb
OBS_MAX_EVENTS=200
DYNAMODB_TABLE_NAME=<table>   # implies dynamodb when set
```

Nothing on the authorization path needs storage. It holds the runtime word-list policy and
the observability event log; both can be absent and Copilot still gets correct answers.

**`memory`** keeps everything in-process and pulls in no dependencies. Events vanish on
restart and are invisible to other instances behind a load balancer. Fine for a single
container; not for anything horizontally scaled where the event log matters.

**`dynamodb`** requires the optional AWS SDK packages:

```bash
npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb
```

Single table, partition key `pk` (String), sort key `sk` (String). On-demand capacity is
plenty. IAM needs `GetItem`, `PutItem`, `Query`, `UpdateItem` and `BatchWriteItem` on it.

---

## Optional endpoints — both off by default

```bash
ENABLE_OBSERVABILITY=false
ENABLE_CONFIG_API=false
CONFIG_API_TOKEN=<strong random secret>
OBS_STORE_PROMPTS=false
PUBLIC_API_BASE=              # only if the dashboard is not same-origin
```

Neither is mounted unless enabled — a request to them returns `404`. A deployment that never
turns them on has no such surface to protect.

When enabled, the **data** routes (`/observability/events`, `/config/policy`) require an `x-config-token` header matching `CONFIG_API_TOKEN`, and are
**disabled outright** when it is unset. Forgetting to configure a token gives you a dark
dashboard, not an open one. The `/observability` page itself is reachable without a header —
a browser cannot set one on a navigation — and is safe because it carries no data; it prompts
for the token and holds it in the tab.

**Conversation content is not retained.** Prompts, planner reasoning, chat history, tool
output values, argument values and the client IP are replaced with `[redacted]` on the way
*in*. Ids, tool names, structure, counts, timings and decisions survive — which is what a
diagnosis is made of. Redacting at write time means the data cannot leak from a route
someone forgot to protect, cannot be read by whoever has database access, and is not in a
backup.

`OBS_STORE_PROMPTS=true` retains it for a debugging session. The store then holds personal
data; treat the setting as temporary.

Restrict these routes at your gateway as well — defence in depth, not instead of.

---

## Server (Node adapter)

```bash
PORT=8080
BIND_HOST=0.0.0.0
MAX_REQUEST_BYTES=2097152     # 2 MiB; larger requests get 413
```

TLS is not handled here. Copilot requires HTTPS; terminate it in the platform in front of
this process — App Service, an ingress controller, a load balancer.

---

## Copilot Studio topics

```bash
EVALUATE_COPILOT_TOPICS=false
```

Topics reach this webhook as pseudo-tools — their `toolDefinition.id` contains `.topic.`
rather than `.action.`. They are not real tool executions, so they are allowed without
consulting the PDP, which keeps duplicate and blank-named entries out of your decision log.
Set `true` to evaluate them like real tools.
