# Changelog

Notable changes per release. Versions follow [semantic versioning](https://semver.org),
with the pre-1.0 convention that breaking changes land in the minor.

## 0.2.0 — 2026-09-10

The first tagged release. `SECURITY.md` asks you to pin a tag rather than track a branch;
until now there was no tag to pin.

Version `0.1.0` was never tagged or published, so nothing below can have broken a
deployment that pinned it. Both breaking changes are listed anyway, because anyone who
cloned `main` before today is running the old behaviour.

### Breaking

- **`ENTRA_ALLOWED_APP_IDS` is now required, and the service refuses to start without it.**
  Validating an Entra token proves the tenant and the audience, not which application
  called. Without an allowlist, any application in your tenant able to obtain a token for
  your audience could drive tool authorization decisions. The setting existed before but
  was unenforced when unset, which produced no error, no warning and no log line — a
  deployment could look correct and be open. It is a startup error rather than a runtime
  warning because a service already answering requests unprotected has failed.

  The value is your Application (client) ID. Power Platform federates into your own app
  registration, so it is known from setup and needs no live traffic to discover. Local
  development without an Entra tenant uses `ALLOW_INSECURE_LOCAL_AUTH` with `AUTH_TOKEN`,
  which is unaffected.

- **Node 20 is now the minimum**, up from 18, and the optional AWS SDK is pinned exactly.
  The declared floor was already wrong: `^3.758.0` resolved to a release requiring Node 20,
  so the DynamoDB storage path was outside SDK support on Node 18 regardless. The newest
  SDK that does support Node 18 carries a critical advisory in `fast-xml-parser`, reachable
  through `@aws-sdk/xml-builder`, and the fix exists only in versions requiring Node 20.
  Node 18 left support in April 2025 and the `nodejs18.x` Lambda runtime is deprecated.

### Fixed

- **A block by a CDN or WAF in front of the PDP is no longer reported as a malformed
  payload.** The PDP answers JSON on every status it owns, so a non-JSON error body did not
  come from the PDP at all. These now carry `errorKind: "upstream-blocked"` and a message
  naming the intermediary, instead of blaming this service's request builder and sending
  the investigation to the wrong team. Behaviour is unchanged — still fail-closed, still
  blocked.

- **One request writes one observability event.** A failed PDP call appended its own event
  and then fell through to the one at the end of the handler, so a single Copilot request
  produced two rows under the same correlation id — one of them without `blockAction`,
  which the dashboard rendered as `N/A` beside the real verdict. It read as the service
  answering the same question twice, differently.

- The observability dashboard's inline script had not parsed since a template-literal
  escaping error was introduced with the token prompt, leaving the page blank.

- The "Active policy" panel is gone. It described state that no longer decided anything.

### Added

- A `gitleaks` scan in CI, over every commit as well as the working tree, alongside the
  existing project-specific identifier check. The two are complementary: one knows this
  project's hostnames and token shapes, the other knows the world's credential formats.

- `docs/TROUBLESHOOTING.md` covers a WAF in front of the PDP — how to recognise it, why it
  is intermittent, and how to fix it.

### Known limitations

- The Lambda adapter is unit-tested but has **not been exercised on real AWS Lambda**. The
  node adapter is the more travelled path.
- Reva PDP evaluation has been measured at 2.6–3.0 s with guardrails in enforce mode,
  against a Copilot budget of roughly 1000 ms, past which Copilot proceeds as if the answer
  were *allow*. Every event records `latency.budgetExceeded`; a sustained run of those means
  enforcement is being bypassed by timeout whatever your policies say. This is a property of
  the PDP, not something this package can fix.
