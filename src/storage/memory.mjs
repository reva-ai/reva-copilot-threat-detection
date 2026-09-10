/**
 * In-process storage. The default, and deliberately so.
 *
 * Nothing on the authorization path needs to persist: the plugin reads the blocked-terms
 * policy and appends an event, and if both were lost on restart Copilot would still get
 * correct answers. Making the durable backend the exception rather than the rule is what
 * lets this package ship with no runtime dependencies, and lets someone evaluate it with
 * `node src/adapters/node/server.mjs` and nothing else.
 *
 * What you give up is real: events live in one process, so they vanish on restart and are
 * invisible to the other instances behind a load balancer, and each instance seeds its own
 * policy row from the environment. For a single container that is fine. For anything
 * horizontally scaled where the event log matters, use a shared backend
 * (`STORAGE_BACKEND=dynamodb`) or ship the events out to your own logging.
 *
 * The event cap is a memory bound, not a retention policy — this is a ring buffer.
 */

const state = {
  policy: null,
  events: [],
  seq: 0
};

function parseCsv(value) {
  if (!value) return [];
  return Array.from(
    new Set(
      String(value)
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean)
    )
  );
}

export function getObsMaxEvents() {
  return Math.max(10, Number(process.env.OBS_MAX_EVENTS || 200));
}

export function sanitizePolicyConfig(config) {
  return {
    blockedTerms: Array.isArray(config?.blockedTerms) ? config.blockedTerms : [],
    blockedToolNames: Array.isArray(config?.blockedToolNames) ? config.blockedToolNames : []
  };
}

export function normalizeStringList(value, fieldName) {
  if (!Array.isArray(value)) {
    throw new Error(`"${fieldName}" must be an array of strings.`);
  }
  const normalized = value
    .map((entry) => {
      if (typeof entry !== "string") {
        throw new Error(`"${fieldName}" must contain only strings.`);
      }
      return entry.trim();
    })
    .filter(Boolean);
  return Array.from(new Set(normalized));
}

export async function getPolicyConfig() {
  if (!state.policy) {
    // Seeded from the environment on first read, matching the durable backends.
    state.policy = {
      blockedTerms: parseCsv(process.env.BLOCKED_TERMS),
      blockedToolNames: parseCsv(process.env.BLOCKED_TOOL_NAMES),
      updatedAt: new Date().toISOString()
    };
  }
  return state.policy;
}

export async function putPolicyConfig(next) {
  state.policy = {
    blockedTerms: normalizeStringList(next.blockedTerms ?? [], "blockedTerms"),
    blockedToolNames: normalizeStringList(next.blockedToolNames ?? [], "blockedToolNames"),
    updatedAt: new Date().toISOString()
  };
  return state.policy;
}

export async function appendObservabilityEvent(event) {
  state.seq += 1;
  state.events.unshift({ id: state.seq, timestamp: new Date().toISOString(), ...event });
  // Bounded so a long-running process cannot grow without limit.
  const cap = getObsMaxEvents();
  if (state.events.length > cap) state.events.length = cap;
  return state.events[0];
}

export async function listObservabilityEvents(limit) {
  const max = Number.isFinite(limit) && limit > 0 ? limit : getObsMaxEvents();
  return state.events.slice(0, max);
}

export async function clearObservabilityEvents() {
  state.events = [];
  return { cleared: true };
}

/** Test seam. Not part of the storage interface. */
export function __reset() {
  state.policy = null;
  state.events = [];
  state.seq = 0;
}
