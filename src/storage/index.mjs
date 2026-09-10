/**
 * Storage selection.
 *
 * The authorization path does not need storage at all. It is used for two optional things:
 * the runtime blocked-terms policy row, and the observability event log. Both can be absent
 * and the plugin still answers Copilot correctly, which is why the default backend keeps
 * everything in memory and pulls in no dependencies.
 *
 * Choosing a backend at startup rather than importing one unconditionally is what keeps the
 * AWS SDK out of a deployment that is not on AWS. `dynamodb.mjs` is imported lazily, so a
 * customer running the Node adapter on App Service never loads it and never needs it
 * installed.
 */

let backend = null;

function chooseBackendName(env) {
  const explicit = String(env.STORAGE_BACKEND || "").trim().toLowerCase();
  if (explicit) return explicit;
  // Historical behaviour: presence of a table name meant DynamoDB. Kept so an existing
  // AWS deployment needs no new variable.
  return env.DYNAMODB_TABLE_NAME ? "dynamodb" : "memory";
}

/**
 * Resolve the configured backend once. Every backend exports the same shape, so callers
 * never learn which one they got.
 */
export async function getStorage(env = process.env) {
  if (backend) return backend;

  const name = chooseBackendName(env);
  if (name === "memory") {
    backend = await import("./memory.mjs");
  } else if (name === "dynamodb") {
    // Lazy, and with a diagnosis rather than a bare module-not-found: the optional
    // dependency being absent is a configuration mistake, not a crash.
    try {
      backend = await import("./dynamodb.mjs");
    } catch (err) {
      throw new Error(
        `STORAGE_BACKEND=dynamodb requires the optional @aws-sdk packages. ` +
          `Install them with: npm install @aws-sdk/client-dynamodb @aws-sdk/lib-dynamodb  (${err.message})`
      );
    }
  } else {
    throw new Error(`Unknown STORAGE_BACKEND "${name}". Use "memory" or "dynamodb".`);
  }

  if (typeof backend.getPolicyConfig !== "function") {
    throw new Error(`Storage backend "${name}" does not implement the storage interface.`);
  }
  return backend;
}

/** Test seam: drop the memoised backend so the next call re-reads the environment. */
export function resetStorage() {
  backend = null;
}

// Thin pass-throughs, so routes read as though storage were a plain module.
export async function getPolicyConfig(...args) {
  return (await getStorage()).getPolicyConfig(...args);
}
export async function putPolicyConfig(...args) {
  return (await getStorage()).putPolicyConfig(...args);
}
export async function appendObservabilityEvent(...args) {
  return (await getStorage()).appendObservabilityEvent(...args);
}
export async function listObservabilityEvents(...args) {
  return (await getStorage()).listObservabilityEvents(...args);
}
export async function clearObservabilityEvents(...args) {
  return (await getStorage()).clearObservabilityEvents(...args);
}
export async function sanitizePolicyConfig(...args) {
  return (await getStorage()).sanitizePolicyConfig(...args);
}
export async function getObsMaxEvents(...args) {
  return (await getStorage()).getObsMaxEvents(...args);
}
