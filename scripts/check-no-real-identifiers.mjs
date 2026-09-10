#!/usr/bin/env node
/**
 * Fails if anything identifying a real deployment has landed in this public repository.
 *
 * The risk is mundane and easy to hit: a GUID pasted from a live tenant while debugging, a
 * hostname copied out of an internal runbook, a token in a scratch example. None of it looks
 * dangerous in a diff. All of it is durable once pushed, and this repository is discoverable
 * by anyone.
 *
 * Placeholders are therefore made *obviously* synthetic — every GUID group is a repeated
 * digit — so "is this real?" is answerable at a glance rather than by lookup.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "coverage"]);
const EXTS = new Set([".mjs", ".js", ".json", ".md", ".yml", ".yaml", ".txt", ".sh", ".ps1"]);

const GUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
/** A GUID is acceptable only if every hex group is one repeated character. */
const isPlaceholder = (g) =>
  g.toLowerCase().split("-").every((part) => /^(.)\1*$/.test(part));

/**
 * Microsoft first-party application ids. These are public constants, identical in every
 * tenant, published in Microsoft's own documentation — the install guide needs them by
 * value. Anything added here must be a documented Microsoft identifier, never a GUID from
 * one of our own or a customer's tenants.
 */
const KNOWN_PUBLIC = new Map([
  ["04b07795-8ddb-461a-bbee-02f9e1bf7b46", "Microsoft Azure CLI (first-party)"]
]);

const RULES = [
  { name: "internal Reva hostname", re: /\b(?:pr|dv)\d{2}\.(?:preview|dev)\.reva\.ai\b/gi },
  { name: "JWT or JWE", re: /\beyJ[A-Za-z0-9_-]{20,}\./g },
  { name: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: "private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g }
];

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) yield* walk(full);
    else if (EXTS.has(path.extname(full))) yield full;
  }
}

let failures = 0;
const SELF = path.join(ROOT, "scripts", "check-no-real-identifiers.mjs");

for (const file of walk(ROOT)) {
  if (file === SELF) continue; // this file names the patterns it hunts for
  const text = readFileSync(file, "utf8");
  const rel = path.relative(ROOT, file);

  for (const guid of text.match(GUID) || []) {
    if (isPlaceholder(guid)) continue;
    if (KNOWN_PUBLIC.has(guid.toLowerCase())) continue;
    console.error(`${rel}: non-placeholder GUID ${guid}`);
    console.error(`  -> replace with a repeated-digit placeholder, e.g. 11111111-1111-1111-1111-111111111111`);
    failures += 1;
  }

  for (const { name, re } of RULES) {
    for (const hit of text.match(re) || []) {
      console.error(`${rel}: ${name} — ${hit.slice(0, 32)}…`);
      failures += 1;
    }
  }
}

if (failures) {
  console.error(`\n${failures} problem(s). This repository is public; see SECURITY.md.`);
  process.exit(1);
}
console.log("No real identifiers found.");
