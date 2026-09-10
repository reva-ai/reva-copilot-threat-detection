# Security

## Reporting a vulnerability

Email **info@reva.ai** with "SECURITY" in the subject. Please include what you found, how to
reproduce it, and what an attacker could do with it. Please do not open a public issue for
anything exploitable.

We will acknowledge within 3 business days and keep you updated until it is resolved. If you
would like credit in the release notes, say so and we will include it.

## What this software is, in security terms

This is an **authorization enforcement point**. Microsoft Copilot Studio calls it before an
agent invokes a tool, and its answer decides whether that tool runs. It therefore sees, on
every call: the user's message, the planner's reasoning, prior tool outputs, the proposed
tool and its arguments, and the identities of the agent, the user and the tenant.

You run it in **your** environment, against **your** Entra tenant. Reva does not operate it
and cannot see your traffic. The decision is delegated to a Reva PDP over HTTPS.

## The threat model you are deploying into

**Two endpoints must be reachable from the public internet** — Microsoft calls them:

| Route | Exposure |
|---|---|
| `POST /validate` | public, Entra-authenticated |
| `POST /analyze-tool-execution` | public, Entra-authenticated |

Everything else is **off by default** and should stay off unless you need it:

| Route | Enabled by | Notes |
|---|---|---|
| `GET`/`PUT /config/policy` | `ENABLE_CONFIG_API=true` | changes what the plugin blocks |
| `/observability*` | `ENABLE_OBSERVABILITY=true` | serves the decision record |

## Controls, and what each one actually buys you

**Token validation.** Every request to the two public routes must carry an Entra bearer
token. Signature, issuer, tenant, audience, expiry and not-before are all checked against
the tenant's published JWKS.

**Caller authorization — set this.** Validating a token proves the right *tenant* and the
right *audience*. It does **not** prove Copilot Studio sent it: any application in your
tenant able to obtain a token for your audience passes. Set `ENTRA_ALLOWED_APP_IDS` to the
Application (client) ID you registered for the integration. Microsoft treats this as the
provider's responsibility, and their own Defender integration enforces the same check.

Left unset, the control is off. It ships that way because the correct value is specific to
your tenant and a wrong GUID in a security control is worse than an absent one.

**Fail closed.** If the PDP cannot be reached, times out, or rejects the request, the answer
is *block* — `blockAction: true`, reason code 103, with wording that names a service failure
rather than a policy decision. `REVA_FAIL_OPEN=true` inverts this and is for debugging only.

**Content is not retained.** Prompts, planner reasoning, chat history, tool output values,
tool arguments and the client IP are redacted **before** anything is written to the event
store. Ids, tool names, structure, counts and timings are kept. `OBS_STORE_PROMPTS=true`
retains the content for a debugging session — the store then holds personal data, so treat
that setting as temporary.

**No runtime dependencies.** The core and both adapters use only the Node standard library.
The AWS SDK is an *optional* dependency, needed only for `STORAGE_BACKEND=dynamodb`. There
is no supply chain to compromise in a default install.

## A limit you should know about

Microsoft allows this webhook roughly **1000 ms** and, past that, proceeds as though the
answer were *allow*. That behaviour is Microsoft's and cannot be overridden by this plugin.
If your PDP is slower than the budget, enforcement is bypassed by timeout regardless of what
the policies say.

Every event records the handler's end-to-end latency and a `budgetExceeded` flag so you can
measure this rather than assume it. **Monitor it.** A sustained run of `budgetExceeded: true`
means you are not actually enforcing.

## Hardening checklist

- [ ] `ENTRA_ALLOWED_APP_IDS` set to your registered Application (client) ID
- [ ] `ENTRA_TENANT_ID` and `ENTRA_AUDIENCE` set; `ALLOW_INSECURE_LOCAL_AUTH` **unset**
- [ ] `REVA_PDP_TOKEN` held in a secret manager, not in plaintext configuration, with a
      rotation owner
- [ ] `REVA_FAIL_OPEN` unset or `false`
- [ ] `REVA_MODE` unset or `enforce` — a deployment left in `monitor` records denials and
      permits every one of them
- [ ] `OBS_STORE_PROMPTS` unset or `false`
- [ ] `ENABLE_OBSERVABILITY` and `ENABLE_CONFIG_API` unset unless needed; when enabled,
      `CONFIG_API_TOKEN` is a strong random value **and** the routes are restricted at your
      gateway as well
- [ ] TLS terminated in front of this process; it does not serve HTTPS itself
- [ ] `budgetExceeded` monitored

## Supported versions

Security fixes are issued for the latest minor release. Pin a tag rather than tracking a
branch.
