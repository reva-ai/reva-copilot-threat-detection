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
 ┌──────────────────┐   1. user asks the agent something
 │  Copilot Studio  │
 │ generative agent │   2. planner decides to call a tool
 └────────┬─────────┘
          │  POST /analyze-tool-execution        (Entra bearer token)
          ▼
 ┌──────────────────────────┐   3. translate Microsoft's payload into a
 │  THIS SERVICE            │      Reva evaluation request
 │  threat-detection webhook│
 └────────┬─────────────────┘
          │  POST /pdp/v2/ai/evaluation          (Reva bearer token)
          ▼
 ┌──────────────────────────┐   4. Cedar policies + guardrails decide
 │  Reva PDP                │      (prompt injection, intent drift)
 └────────┬─────────────────┘
          │  { "decision": true | false }
          ▼
 back to Copilot Studio as { "blockAction": false | true }
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
| Node.js 18+ hosting | AWS Lambda + API Gateway (this package) or Azure App Service |

> **The verified-domain requirement kills the obvious shortcuts.** `ngrok`, `*.onrender.com`
> and similar tunnels cannot be used as the Application ID URI: Entra refuses any HTTPS
> identifier on a domain you have not verified. Bare `*.azurewebsites.net` is often refused
> for the same reason. Budget for a real subdomain (e.g.
> `threatdetection.yourcompany.com`) before you start — retrofitting it means redoing §4,
> because the federated credential encodes the URL.

---

## 3. Deploy the service

### Option A — AWS Lambda + API Gateway (this package)

```bash
./build.sh
```

That produces one zip per route in `dist/`. Each contains `index.mjs`, `shared/` and
`node_modules/`; the Lambda handler is `index.handler` on Node.js 18+ or 24.x.

Create one Lambda per zip and route them through API Gateway (HTTP API):

| Route | Zip | Public |
|---|---|---|
| `POST /validate` | `validate.zip` | yes — Microsoft calls it |
| `POST /analyze-tool-execution` | `analyze-tool-execution.zip` | yes — Microsoft calls it |
| `GET /observability` + `/observability/events`, `/observability/policy` | matching zips | **no — restrict these** |
| `GET`/`PUT /config/policy` | `config-policy-*.zip` | no |

All Lambdas share one DynamoDB table (`DYNAMODB_TABLE_NAME`) for the policy row and the
event log. See `envars.md` for the full per-Lambda variable list.

### Option B — Azure App Service

Publish as **Code**, runtime **Node 18+**, OS **Linux**. Set the variables from `envars.md`
under *Settings → Environment variables*.

Bind your custom domain: a **CNAME** from your subdomain to the default hostname, plus the
**`asuid.<subdomain>` TXT record** Azure asks for. Wait for both to resolve before §4 — the
Application ID URI cannot be set on an unverified domain.

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

Until you do, the endpoint accepts a token from **any** application in your tenant that can
obtain one for your audience. Microsoft treats this as the provider's responsibility, not the
platform's.

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

# Where we send the authorization question (Reva)
REVA_PDP_URL=https://api.<env>.reva.ai/pdp/v2/ai/evaluation
REVA_POLICY_STORE_ID=<policy store uuid>
REVA_PDP_TOKEN=<v2 api token>

# Storage
DYNAMODB_TABLE_NAME=<table>
```

`ENTRA_AUDIENCE` must be byte-identical to the Application ID URI from §4.1. This is the
most common misconfiguration.

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
`envars.md` under *Writing open policies*.

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
`REVA_FAIL_OPEN` in `envars.md`.

`envars.md` documents every remaining variable, including timeouts, fail-open, retry and
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
npm test                      # 80 unit tests, no network needed
npm run local:fixture:allow   # drives the handler with a real Microsoft payload
```

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

| Symptom | Cause | Fix |
|---|---|---|
| `AADSTS650057` — invalid resource, empty valid-resource list | The CLI is not authorized to request a token for your API | §4.1 step 3: add client `04b07795-8ddb-461a-bbee-02f9e1bf7b46` with `access_as_user` |
| `AADSTS700213` — no matching federated identity record | The asserted subject differs from the one you registered | Base64url-decode the subject in the error; create a credential for exactly that string. Wait 2–5 min. Delete-and-recreate rather than edit |
| `AADSTS500011` — resource principal not found in tenant | Application ID URI does not match the endpoint Power Platform requested, or is not on a verified domain | Set the Application ID URI to the exact base URL from §6, on a verified domain, and set `ENTRA_AUDIENCE` to the same string |
| `ExternalServiceTokenAcquisitionError` on Save | Entra could not issue a token at all | Work through the three rows above in order |
| `ExternalServiceTimeoutError`, or ~4s responses | Outbound 443 to `login.microsoftonline.com` blocked, or cold start | Open egress (§3). JWKS is cached for 5 minutes after the first success |
| Every tool call blocked, reasonCode **103** | The service could not reach, authenticate to, or satisfy the Reva PDP | Read `errorKind` on the observability event: `transport` / `timeout` → check `REVA_PDP_URL` and egress; `auth` → the token is not a **v2** token (§7); `invalid-payload` → the PDP rejected the request body, and its own reason is on the event |
| One chat blocks every call from some point on, while other chats are fine | A prior turn in `session.messages` has no captured answer. The PDP answers `400 invalid session: session.messages[N].response…is required`, and that 400 carries `decision:false` | Current builds drop unanswered turns before sending, and classify a 400 as `invalid-payload` rather than a policy deny. Deploy the current build |
| PDP `401` | v1 token against the v2 endpoint | Issue a v2 token |
| PDP `403` *"requires a Tool resource, resolved …"* or *"requires action invokeTool"* | The entity **type** or the **action** is not what the schema pairs. Ids are free-form; types and actions are not | Fix the type/action pairing. This is not a policy decision, despite the 403 — the reason text is on the observability event |
| `400 managed context records are not supported at managed context.<key>` | A record was added to `context` outside the API's allowlist | Records are allowed only for `conversation`, `hops`, `chatHistory`, `environment` and `onBehalfOf`. Everything else must be a flat scalar or a scalar array. The error names the offending key |
| A Cedar policy publishes but never fires | Context attribute name mismatch | Cedar matches keys exactly and a missing key is not an error — it fails the `has` guard. Check `REVA_CONTEXT_ATTR_PREFIX` against your store |
| No `/analyze-tool-execution` events at all | The agent never called a tool, or it is not a generative agent with generative orchestration | §8.3 |
| `400 Request body must include inputParameters` | An older build; Copilot sends `inputValues` and `previousToolsOutputs` | Deploy the current build, which accepts both spellings |
| Blocked-term policies fire on the agent's own refusal text | Prior block messages being fed back as history | Current builds replace them with a neutral marker; deploy the current build |

---

## 10. Security checklist before go-live

- [ ] `ENTRA_ALLOWED_APP_IDS` is set. Without it, any application in your tenant that can get
      a token for your audience can drive this webhook — validating the token proves the
      tenant and the audience, not the caller. Read `callerAppId` off an observability event
      after one real tool call, then pin it.
- [ ] `CONFIG_API_TOKEN` is set, so the observability data routes are enabled *and* protected.
      Unset, they are disabled; set, they require `x-config-token`. Restrict them at the
      gateway as well — defence in depth, not instead of.
- [ ] `OBS_STORE_PROMPTS` is unset or `false`, so conversation content is not retained. Turn it
      on only for a debugging session, and remember the store then holds personal data.
- [ ] `ALLOW_INSECURE_LOCAL_AUTH` is unset in production.
- [ ] `CONFIG_API_TOKEN` is a strong random value, stored as a secret.
- [ ] `REVA_PDP_TOKEN` is stored in a secret manager (Key Vault / Secrets Manager), not in
      plaintext app settings, and has a rotation owner.
- [ ] `REVA_FAIL_OPEN` is unset or `false`.
- [ ] `REVA_MODE` is unset or `enforce` — a service left in `monitor` records denials and
      permits every one of them.
- [ ] `entityResolution.user` on recent events begins `conversation-metadata:`. Anything else
      means the end user was absent from the payload and the transport identity stood in.
- [ ] On a **named-entity** policy store, all three id maps are populated and no recent
      event shows an `entityResolution` beginning `slug:`. (Not needed for open policies.)
- [ ] The Power Platform error behavior matches your intended posture (§6).
- [ ] Someone owns the Reva decision log — it is the only place guardrail verdicts appear.
