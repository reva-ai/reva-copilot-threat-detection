# Reva threat detection for Microsoft Copilot Studio

An **external threat detection provider** for Microsoft Copilot Studio. Copilot calls this
service before an agent invokes a tool; it asks a Reva policy decision point whether the
call is authorized, and answers allow or block.

You run it in your own environment, against your own Entra tenant. Reva does not operate it
and does not see your traffic.

```
 ┌──────────────────┐   1. a user asks the agent for something
 │  Copilot Studio  │
 │ generative agent │   2. the planner decides to call a tool
 └────────┬─────────┘
          │  POST /analyze-tool-execution        (Entra bearer token)
          ▼
 ┌──────────────────────────┐   3. translate Microsoft's payload into a
 │  THIS SERVICE            │      Reva evaluation request
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

## Two things that surprise everyone

**The webhook only fires for tool calls.** If an agent answers from the model alone, this
service is never called. "The integration looks dead" is almost always this.

**It is an environment-level setting**, configured per Power Platform environment, and it
applies only to **generative** agents using generative orchestration. Classic agents never
call it, and there is no tenant-wide switch.

## Run it

Requires **Node 18+** and nothing else — no runtime dependencies.

```bash
git clone https://github.com/reva-ai/reva-copilot-threat-detection.git
cd reva-copilot-threat-detection
npm test        # 144 tests, no network needed

ENTRA_TENANT_ID=<your tenant>            \
ENTRA_AUDIENCE=https://td.example.com    \
ENTRA_ALLOWED_APP_IDS=<your app id>      \
REVA_PDP_URL=https://api.<env>.reva.ai/pdp/v2/ai/evaluation \
REVA_POLICY_STORE_ID=<store>             \
REVA_PDP_TOKEN=<v2 token>                \
npm start
```

That serves `POST /validate` and `POST /analyze-tool-execution` on `:8080`. Put TLS in front
of it — Copilot requires HTTPS and this process deliberately does not terminate it.

### Where it can run

| Host | How |
|---|---|
| Azure App Service, Container Apps, ECS, Kubernetes, a VM | `npm start` — the Node adapter |
| AWS Lambda | `src/adapters/lambda/index.mjs`, one export per route |
| Anywhere else | routes are plain `(request) → response` functions; write ~30 lines of adapter |

Full walkthrough — Entra app registration, Power Platform setup, verification, and an
AADSTS troubleshooting table — is in **[docs/INSTALL.md](docs/INSTALL.md)**. Every
configuration variable is in **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**.

## Before you put it in front of real traffic

Three settings decide whether this is actually enforcing anything. All are covered in
**[SECURITY.md](SECURITY.md)**; these are the ones people miss.

**Set `ENTRA_ALLOWED_APP_IDS`.** Validating the token proves the right tenant and audience —
not that Copilot Studio sent it. Without this, any application in your tenant that can get a
token for your audience can drive the webhook. Microsoft treats this as the provider's job,
and their own Defender integration enforces the same check.

**Start in `REVA_MODE=monitor`.** Your policies have never met your real traffic. Monitor
evaluates for real, records every would-be denial with the reason, and lets traffic through.
Switch to `enforce` once that list holds no surprises.

**Watch `budgetExceeded`.** Microsoft allows this webhook about **1000 ms** and, past that,
proceeds as if the answer were *allow*. That is Microsoft's behaviour and this plugin cannot
override it. Every event records the end-to-end latency and whether it exceeded the budget —
a sustained run of exceedances means you are not enforcing, whatever your policies say.

## What it sends, and what it keeps

Copilot's payload is translated into a Reva evaluation request: the acting agent, the tool,
the originating user, the turn's conversation and hops, and a sentence describing what this
particular hop does. That last one matters — sending the user's prompt instead would compare
the hop against itself, and no amount of drift would ever register.

Nothing conversational is **retained**. Prompts, planner reasoning, chat history, tool
outputs, arguments and the client IP are redacted before anything reaches the event store.
Ids, tool names, structure, counts, timings and decisions are kept, which is what diagnosing
a problem actually needs.

## Layout

```
src/core/       host-agnostic: Entra verification, payload building, PDP client, redaction
src/routes/     one function per endpoint, taking a request and returning a response
src/adapters/   Lambda and Node HTTP — translation only, no logic
src/storage/    in-memory by default; DynamoDB is optional and lazily loaded
examples/       synthetic Copilot payloads, also used by the tests
docs/           install, configuration, troubleshooting
```

## Contributing and support

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). For anything
security-sensitive, email **info@reva.ai** rather than opening an issue.

Licensed under [Apache-2.0](LICENSE).
