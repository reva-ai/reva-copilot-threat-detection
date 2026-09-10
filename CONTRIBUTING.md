# Contributing

## Before you open a pull request

```bash
npm test                                   # 144 tests, no network
node scripts/check-no-real-identifiers.mjs # nothing real may land in a public repo
```

Both run in CI, along with `npm audit` and a check that the package still has **zero**
runtime dependencies.

## Two rules that are not negotiable

**No real identifiers.** This repository is public. Tenant, user, agent and application
GUIDs, internal hostnames, tokens and client IPs must never appear — including in comments
and example payloads. Placeholders are deliberately obvious: every GUID group is a repeated
character, so `11111111-1111-1111-1111-111111111111` reads as synthetic at a glance. The
check above enforces this.

**No runtime dependencies.** The core and both adapters use only the Node standard library.
This is a security control, not an aesthetic: customers run this in front of their agents,
and a package with no supply chain cannot have one compromised. The AWS SDK is optional and
lazily imported for DynamoDB storage only. If you believe a dependency is genuinely
necessary, open an issue first.

## Adding a host adapter

Routes are plain functions:

```js
async function handleX(request) -> { statusCode, headers, body }
// request: { method, path, headers, body /* raw string */ }
```

An adapter translates its host's request into that shape and the response back out. It
should contain no logic — see `src/adapters/` for two examples of about thirty lines each.

## Tests

`node:test`, no framework. Prefer a test that drives a route over one that asserts on an
internal helper; the routes are the contract. Security controls need a test that shows the
control **denying**, not only permitting — a test that only checks the happy path would
still pass if the control were removed.

## Commit messages

Explain why the change is correct, not what the diff shows. If behaviour changed because of
something observed from a live system, say what was observed.
