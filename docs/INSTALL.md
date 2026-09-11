# Installing the Reva threat-detection webhook for Microsoft Copilot Studio

This service is an **external threat detection provider** for Copilot Studio. Microsoft calls
it every time a generative agent's planner is about to invoke a tool; the service asks the
Reva PDP whether that call is authorized and answers allow or block.

Nothing here assumes prior knowledge of the service. Work top to bottom — each section
depends on the one before it.

**Time required:** about two hours, most of it waiting for DNS and Entra propagation.

---

## 1. How it fits together

```
 ┌────────────────────────────┐
 │  Copilot Studio            │   1. user asks the agent something
 │  generative agent          │   2. planner decides to call a tool
 └────────────────────────────┘
      │                   ▲
      │ POST              │ { "blockAction": false | true }
      │ /analyze-tool-    │
      │ execution         │ 5. THIS SERVICE maps the decision onto
      │ (Entra token)     │    Microsoft's schema and answers Copilot
      ▼                   │
 ┌────────────────────────────┐   3. translate Microsoft's payload into a
 │  THIS SERVICE              │      Reva evaluation request
 │  threat-detection webhook  │
 └────────────────────────────┘
      │                   ▲
      │ POST              │ { "decision": true | false }
      │ /pdp/v2/ai/       │
      │ evaluation        │
      │ (Reva token)      │
      ▼                   │
 ┌────────────────────────────┐   4. Cedar policies + guardrails decide
 │  Reva PDP                  │      (prompt injection, intent drift)
 └────────────────────────────┘

 The PDP never talks to Copilot. It answers THIS SERVICE, which owns the
 translation in both directions — Microsoft's payload in, Microsoft's
 blockAction out.
```

Two things follow from this shape and cause most of the confusion during setup:

- **The webhook only fires for tool calls.** If an agent answers from the model alone, this
  service is never called. "The integration looks dead" is almost always this.
- **It is an environment-level setting**, not a per-agent one, and it applies only to
  **generative** agents using **generative orchestration**. Classic agents never call it.

---

## 2. Prerequisites

| | Why |
|---|---|
| **Power Platform Administrator** role | The threat-detection settings are invisible or read-only without it |
| A **domain verified in your Entra tenant** | The Application ID URI must be an HTTPS URL on a domain you own and have verified. This is the single hardest requirement — see the warning below |
| An Entra tenant admin who can register an app | You will create one app registration with a scope and a federated credential |
| Reva policy store id, PDP URL, and a **v2** API token | From your Reva tenant. A v1 token will not work — see §7 |
| Node.js 20+ hosting | AWS Lambda + API Gateway (this package) or Azure App Service |

> **The verified-domain requirement kills the obvious shortcuts.** `ngrok`, `*.onrender.com`
> and similar tunnels cannot be used as the Application ID URI: Entra refuses any HTTPS
> identifier on a domain you have not verified. Bare `*.azurewebsites.net` is often refused
> for the same reason. Budget for a real subdomain (e.g.
> `threatdetection.yourcompany.com`) before you start — retrofitting it means redoing §4,
> because the federated credential encodes the URL.

---

## 3. Deploy the service

Requires **Node 20 or newer**. A default install has **no dependencies** — nothing to
`npm install` unless you opt into DynamoDB storage.

Only two routes need to be publicly reachable, because they are the two Microsoft calls:

| Route | Public |
|---|---|
| `POST /validate` | yes |
| `POST /analyze-tool-execution` | yes |

Everything else is off unless you switch it on, and returns `404` while off.

### Deploy it near the Power Platform environment

**This is a latency requirement, not a preference.** Copilot allows this webhook about
1000 ms, and on a distant deployment most of that is spent on the network before your code
runs at all.

Measured from an Indian Power Platform region against a `us-east-1` API Gateway, on a
connection that was not already open:

| | |
|---|---|
| DNS | ~3 ms |
| TCP connect | ~230 ms |
| TLS handshake | ~240 ms more |
| **Total before the request body is sent** | **~470 ms** |
| Round trip, no application work at all | **760–875 ms** |

That leaves under 250 ms for authentication, the PDP call and the response — which is not
enough, so requests intermittently exceed the budget. What happens then depends on the error
behaviour set in the Power Platform admin center: the documented default is to proceed as if
you had answered *allow*, but an environment set to **Block the query** refuses instead, and
the user sees `securityWebhookBlocked` on calls your own event log records as allowed.

Deploy in the region closest to the Power Platform environment. If you cannot, put a CDN with
edge TLS termination in front of the endpoint so the handshake completes near the caller
rather than across an ocean.

### Option A — any Node host (recommended)

Azure App Service, Azure Container Apps, ECS or Fargate, Kubernetes, a VM, on-prem:

```bash
git clone https://github.com/reva-ai/reva-copilot-threat-detection.git
cd reva-copilot-threat-detection
npm test          # no network required
npm start         # listens on $PORT, default 8080
```

That is the whole deployment. Put TLS in front of it — Copilot requires HTTPS and this
process deliberately does not terminate it, because that job belongs to the platform you
are already running (App Service, an ingress controller, a load balancer).

**Azure App Service specifics.** Publish as **Code**, runtime **Node 20+**, OS **Linux**.
Set the variables under *Settings → Environment variables*. Bind your custom domain with a
**CNAME** to the default hostname plus the **`asuid.<subdomain>` TXT record** Azure asks
for, and wait for both to resolve before §4 — the Application ID URI cannot be set on an
unverified domain.

**Containers.** There is no Dockerfile in this repo on purpose: a three-line one built on
whichever `node:` base image your organisation has already approved is better than one we
pick for you.

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY . .
CMD ["node", "src/adapters/node/server.mjs"]
```

### Option B — AWS Lambda

`src/adapters/lambda/index.mjs` exports one handler per route, so each can sit behind its
own function and its own IAM role:

| Route | Export | Lambda handler |
|---|---|---|
| `POST /validate` | `validate` | `index.validate` |
| `POST /analyze-tool-execution` | `analyzeToolExecution` | `index.analyzeToolExecution` |

Zip the repository (or just `src/`), set the handler as above, runtime Node 20+. Route both
through API Gateway — HTTP API or REST API — preserving the `Authorization` and
`x-ms-correlation-id` headers, and without rewriting the paths.

On Lambda you will usually want `STORAGE_BACKEND=dynamodb`, since in-memory storage is
per-container and containers come and go. That is the one case needing
`npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb`.

### Option C — something else

Routes are plain functions:

```js
async function handleX(request) -> { statusCode, headers, body }
// request: { method, path, headers, body /* raw string */ }
```

An adapter translates your host's request into that shape and the response back out, with
no logic of its own. Both shipped adapters are about thirty lines; see `src/adapters/`.

### Either way: outbound network access

The service makes **two** outbound HTTPS calls. Both must be allowed on port 443:

| Host | Why | Symptom if blocked |
|---|---|---|
| `login.microsoftonline.com` | Fetches Entra JWKS to validate Microsoft's bearer token | Requests hang, then Copilot reports `ExternalServiceTimeoutError` |
| Your Reva PDP host (e.g. `api.<your-env>.reva.ai`) | The authorization decision | Every tool call blocked with reasonCode 103 |

The first of these has caused a production outage before and is easy to miss, because
nothing in the app's own configuration mentions it.

---

## 4. Register the Entra application

> **Microsoft can do this section for you.** They publish
> [`Create-CopilotWebhookApp.ps1`](https://www.powershellgallery.com/packages/Create-CopilotWebhookApp/1.0.1),
> which creates the app registration *and* the federated credential in one command, and is
> their recommended path:
>
> ```powershell
> .\Create-CopilotWebhookApp.ps1 -TenantId "<tenant>" -Endpoint "https://threatdetection.yourcompany.com" `
>   -DisplayName "Copilot Threat Detection" -FICName "ProductionFIC"
> ```
>
> It prints the App ID you need in §6. Use `-DryRun` to validate without creating anything.
> The manual steps below remain accurate and are worth reading either way — they explain what
> the script produces and are what you will debug against if it fails.


Microsoft Entra admin center → **App registrations** → **New registration**. Name it
something like `Copilot Threat Detection Webhook`. Single tenant. No redirect URI.

Record the **Application (client) ID** — Power Platform asks for it in §6.

### 4.1 Expose an API

App → **Expose an API**:

1. **Application ID URI** → set it to your service's **base URL**, exactly:
   ```
   https://threatdetection.yourcompany.com
   ```
   **Not** `api://<client-id>`. Power Platform requests a token whose resource *is* the
   endpoint URL you register in §6, and the Application ID URI must match that string or you
   get `AADSTS500011`. No trailing slash, no path.

2. **Add a scope**:
   - Scope name: `access_as_user`
   - Who can consent: **Admins only**
   - State: **Enabled**

   Use a *scope*, not an *App role*. App roles surface as `roles` in the token and are not
   what this flow uses.

3. **Authorized client applications** → *Add a client application*:
   - Client ID `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Microsoft Azure CLI)
   - Tick `access_as_user`

   This is only needed so you can mint a test token with `az` in §8. Without it `az` returns
   `AADSTS650057`.

### 4.1a Note the Application (client) ID

Keep the **Application (client) ID** to hand — it is not only what Power Platform asks for in
§6, it is also the identity that will call you. Power Platform federates into this app, so the
`appid` claim on every incoming token equals this value.

Set it as `ENTRA_ALLOWED_APP_IDS` so only that application can drive the webhook. Every
observability event records the observed `callerAppId`, so you can confirm the two match
before relying on it.

**The service will not start without this.** Microsoft treats pinning the caller as the
provider's responsibility rather than the platform's, and a token that proves only the
tenant and the audience would let any application in your tenant drive tool authorization.
Rather than warn about that at runtime, the process refuses to start and names the variable.
You do not need a live call to find the value — it is on the app registration's overview
page, above.

### 4.2 Federated identity credential

App → **Certificates & secrets** → **Federated credentials** → **Add credential**:

| Field | Value |
|---|---|
| Scenario | **Other issuer** |
| Issuer | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` |
| Audience | `api://AzureADTokenExchange` (the default — leave it) |
| Type | **Explicit subject identifier** |
| Subject | see below |
| Name | anything, e.g. `copilot-threat-prod` |

The subject encodes your tenant and your endpoint:

```
/eid1/c/pub/t/<base64url of tenant GUID BYTES>/a/m1WPnYRZpEaQKq1Cceg--g/<base64url of endpoint URL>
```

The middle segment `m1WPnYRZpEaQKq1Cceg--g` is a Microsoft constant — use it verbatim.

Generate the two variable parts:

```bash
node -e '
const tenant = "00000000-0000-0000-0000-000000000000";   // <-- your tenant id
const endpoint = "https://threatdetection.yourcompany.com";  // <-- your base URL
const b64u = b => Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const h = tenant.replace(/-/g,"");
const p = i => parseInt(h.slice(i*2, i*2+2), 16);
// .NET Guid.ToByteArray() is mixed-endian: the first three groups are little-endian.
const bytes = Buffer.from([p(3),p(2),p(1),p(0), p(5),p(4), p(7),p(6), p(8),p(9),p(10),p(11),p(12),p(13),p(14),p(15)]);
console.log("tenant  :", b64u(bytes));
console.log("endpoint:", b64u(Buffer.from(endpoint,"utf8")));
'
```

> **The byte order is the trap.** `Guid.ToByteArray()` reverses the first three groups, so a
> naive hex-to-bytes conversion produces a subject that looks right and never matches.

> **Microsoft does not always assert the same subject.** On some hosts it presents the base
> URL, on others the base URL plus `/validate`. You cannot predict which. Create the base-URL
> credential first; if §6 fails with `AADSTS700213`, base64url-decode the subject quoted in
> that error and add a second credential for exactly that string. Creating all three
> up front (`…`, `…/validate`, `…/analyze-tool-execution`) is a reasonable shortcut.

> Entra takes **2–5 minutes** to propagate. If you edit a credential and it still fails,
> delete it and recreate it rather than editing again — stale values persist.

---

## 5. Configure the service

Minimum for a Copilot + Reva deployment:

```bash
# Who we trust to call us (Microsoft)
ENTRA_TENANT_ID=<your tenant guid>
ENTRA_AUDIENCE=https://threatdetection.yourcompany.com   # MUST equal the Application ID URI

# Only this application may call us (see §4.1a)
ENTRA_ALLOWED_APP_IDS=<Application (client) ID>

# Where we send the authorization question (Reva)
REVA_PDP_URL=https://api.<your-env>.reva.ai/pdp/v2/ai/evaluation
REVA_POLICY_STORE_ID=<policy store uuid>
REVA_PDP_TOKEN=<v2 api token>
```

That is the whole required set. Storage defaults to in-memory and needs no configuration;
add `STORAGE_BACKEND=dynamodb` only if you need events to outlive a restart or be shared
across instances.

`ENTRA_AUDIENCE` must be byte-identical to the Application ID URI from §4.1. This is the
most common misconfiguration.

Every remaining variable, with its default, is in
[CONFIGURATION.md](CONFIGURATION.md).

### Map your entities (optional)

Microsoft and Reva share no identifiers. Microsoft sends Entra and Dataverse GUIDs; Reva
uses topology slugs. Without maps the service slugifies the Copilot Studio *display name*.

**Whether you need this depends on how your policies are written.** Entity **ids are
free-form** — the PDP evaluates ids that exist nowhere in the store. What it checks is the
entity **type** and the **action**, which come from the schema:

| Policy style | Maps |
|---|---|
| **Open** — "any Agent may invoke this Tool when …" | **not required.** Matching is by type and condition, so an unregistered id is ordinary traffic |
| **Named-entity** — "`underwriter-copilot` may call `fetch-risk-score`" | **required.** The ids must line up with what the store holds |

Maps are worth setting either way for legible decision logs: `underwriter-copilot` beats
`33333333-3333-3333-3333-333333333333` when you are reading a trace.

**Writing open policies?** The service sends Copilot's own metadata as context scalars —
`tenantId`, `channelId`, `agentEnvironmentId`, `agentIsPublished`, `copilotToolType` — plus the
schema's own `timestamp` and `sourceIp` — so a rule can
test the circumstances rather than name an entity. Add `REVA_USER_GROUPS_MAP` to also declare
each user's `UserGroup` parents with the request, which lets a policy say
`principal in UserGroup::"Underwriters"` without registering anyone. Both are covered in
[CONFIGURATION.md](CONFIGURATION.md) under *What the policy can decide on*.

```bash
REVA_PRINCIPAL_ID_MAP={"<entra-user-guid>":"<reva-user-id>"}
REVA_AGENT_ID_MAP={"<copilot-agent-guid>":"<reva-agent-id>"}
REVA_TOOL_ID_MAP={"<full toolDefinition.id>":"<reva-tool-id>"}
```

Get the Microsoft-side ids from the observability page (§8) — every event shows the raw
`conversationMetadata` and `toolDefinition`. Get the Reva-side ids from your topology.

On a named-entity store, watch `entityResolution` on the observability events: a value
beginning `slug:` means no map matched, and a Copilot Studio rename would silently change
that id.

### Start in monitor mode

```bash
REVA_MODE=monitor
```

Your policies have never met your real traffic. In `monitor` the PDP is called for real and
the verdict is recorded, but the call proceeds either way — so you can read what *would* have
been refused, on production traffic, before anything breaks for a user. Each would-be denial
appears on the observability event as `monitorWouldDeny`, with the PDP's own reason.

Switch to `REVA_MODE=enforce` (the default) once that list is empty of surprises.

Monitor mode relaxes only a real policy **deny**. A PDP fault still fails closed — see
`REVA_FAIL_OPEN` in [CONFIGURATION.md](CONFIGURATION.md).

[CONFIGURATION.md](CONFIGURATION.md) documents every remaining variable, including timeouts, fail-open, retry and
history bounds.

---

## 6. Turn it on in Power Platform

Power Platform admin center → **Security** → **Threat detection** → **Additional threat
detection** → select your environment → **Set up**.

1. Toggle on **Allow Copilot Studio to share data with a threat detection provider**
2. **Azure Entra App ID** → the Application (client) ID from §4
3. **Endpoint link** → your **base URL only**:
   ```
   https://threatdetection.yourcompany.com
   ```
   Do **not** append `/validate` or `/analyze-tool-execution`. Power Platform appends those
   itself.
4. **Error behavior** → **Block the query** (recommended — see the note below)
5. **Save**

**Save immediately calls `POST /validate` against your endpoint.** This is where every
Entra misconfiguration surfaces; §9 decodes the errors.

> **On error behavior.** Microsoft's budget is about one second, and its own default on
> timeout is to *allow*. Reva evaluations with guardrails in enforce mode can take longer
> than that. This service already fails closed on its own (it answers `blockAction: true`
> rather than erroring), so this setting is the backstop for the case where the service
> itself is unreachable. **Block the query** keeps the whole path fail-closed;
> **Allow the agent to respond** favours availability over enforcement. Choose deliberately.

---

## 7. A note on the Reva token

A token that works against `/pdp/access/v1/ai/evaluation` returns **401** against
`/pdp/v2/ai/evaluation`. Issue a fresh token for v2.

The failure looks like an authentication problem rather than a version problem, so it is
easy to misdiagnose. The service distinguishes them: a 401 with no decision body is reported
as `errorKind: "auth"`, never as a policy block.

---

## 8. Verify

### 8.1 The service is reachable

```bash
curl -i -X POST "https://threatdetection.yourcompany.com/validate?api-version=2025-05-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-ms-correlation-id: 11111111-1111-1111-1111-111111111111"
```

Expect `200` and `{"isSuccessful": true, "status": "OK"}`.

Mint `$TOKEN` with:

```bash
az login --tenant <TENANT_ID> --allow-no-subscriptions
az account get-access-token --resource "https://threatdetection.yourcompany.com" --query accessToken -o tsv
```

("No subscriptions found" is normal for an Entra-only user — that is what
`--allow-no-subscriptions` is for.)

### 8.2 A tool call is evaluated

```bash
npm test    # no network needed
```

To drive the running service with a Microsoft-shaped payload, post one of the bundled
examples at it:

```bash
curl -sS -X POST "http://localhost:8080/analyze-tool-execution?api-version=2025-05-01" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data @examples/payloads/microsoft-analyze-allow.json
```

Expect `{"blockAction": false}` or a block with a reason. `examples/payloads/` also contains
a blocked-tool case and a multi-turn conversation.

### 8.3 End to end in Copilot Studio

In an agent that actually calls a tool, ask something that triggers one. Then open
`/observability` and confirm an `/analyze-tool-execution` event appears with the decision.

If nothing appears, the agent answered from the model without calling a tool. Add an
explicit instruction such as *"When the user asks for X, always invoke the Y tool first. Do
not answer without tool output."*

### 8.4 The payload is shaped correctly

Every observability event carries a `payloadShape`:

```json
"payloadShape": { "conversation": 2, "hops": 2, "sessionTurn": 3, "sessionMessages": 2 }
```

**`conversation` and `hops` must always be equal.** They are the same turn counted two ways;
a divergence is a defect, and this is the cheapest place to see it.

Then read the **Reva decision log**. The client response is only `{"decision": …}` — no
score, no chain, no reason — so guardrail verdicts (prompt injection, intent drift) are
visible *only* in the decision log. Budget for that: you cannot assert on guardrail
behaviour from this side.

---

## 9. Troubleshooting

Entra errors, PDP errors, and what to read off an observability event when something is
wrong: **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.

## 10. Before go-live

The hardening checklist lives with the rest of the security posture in
**[../SECURITY.md](../SECURITY.md)** — one copy, so it cannot drift out of step with the
code.

Three that catch people out:

- **`ENTRA_ALLOWED_APP_IDS` is set.** Without it, any application in your tenant that can
  obtain a token for your audience can drive this webhook.
- **`REVA_MODE` is `enforce`** when you are ready. A deployment left in `monitor` records
  every denial and permits every one of them.
- **`budgetExceeded` is monitored.** Microsoft's ~1000 ms budget is not negotiable from
  here; a sustained run of exceedances means you are not enforcing.
