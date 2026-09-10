/**
 * Microsoft identifiers -> Reva entity ids.
 *
 * There is no shared identifier space between the two systems. Microsoft speaks in Entra
 * object GUIDs and Power Platform component ids; Reva speaks in hand-authored topology
 * slugs. Three mappings are needed and only one of them has a clean key:
 *
 *   conversationMetadata.user.id   Entra GUID   -> User.externalId is a real join key
 *   conversationMetadata.agent.id  Dataverse GUID -> the Agent entity has NO externalId field
 *   toolDefinition.id              "pub_X.action.Y_nAl" -> the "_nAl" suffix is a Power
 *                                  Platform-generated opaque token, not derived from the
 *                                  tool name and not stable across solution re-imports
 *
 * So the id is unusable for tools and agents, and slugifying the DISPLAY NAME is the only
 * thing that works without configuration.
 *
 * MAPPING IS COSMETIC, NOT LOAD-BEARING. Verified against pr06 on 2026-09-10: entity ids are
 * free-form strings. A request naming ids that exist nowhere in the store — raw Entra and
 * Dataverse GUIDs, never ingested — is evaluated normally. What the API does constrain is
 * the entity TYPE and the ACTION, which come from the schema:
 *   resource {type:"Widget"}   -> 403 invokeTool requires a Tool resource, resolved "Widget"
 *   action   "frobnicate"      -> 403 Tool resource requires action invokeTool
 * Types and actions must be right; ids need only be consistent.
 *
 * This did not use to be true, and the difference is the policy store rather than the API.
 * A store built on named-entity policies auto-permits each connected edge, so an entity with
 * no edge had no permit and was denied by omission — which is why an earlier version refused
 * unmapped ids up front. A store written with open policies ("any Agent may invoke this Tool
 * when ...") matches on type and condition, so an id nobody registered is ordinary traffic
 * and refusing it locally only blocks calls the PDP would have allowed.
 *
 * What the maps still buy is READABILITY and named-policy compatibility: a decision log
 * reading `underwriter-copilot` is worth more than `33333333-3333-3333-3333-333333333333`,
 * and a store that does name entities still needs the ids to line up. Which rung answered is
 * reported on every event via `entityResolution`, so an unmapped id stays visible.
 */

/** Parse a JSON object env var into a plain map; {} on missing/invalid input. */
function parseJsonObjectEnv(raw) {
  if (!raw || typeof raw !== "string") return {};
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" && !Array.isArray(obj) ? obj : {};
  } catch {
    return {};
  }
}

/** "Underwriter Copilot" -> "underwriter-copilot" */
export function slugify(value, fallback = "") {
  const slug = String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || fallback;
}

export function buildMappingConfigFromEnv(env = process.env) {
  return {
    users: parseJsonObjectEnv(env.REVA_PRINCIPAL_ID_MAP),
    agents: parseJsonObjectEnv(env.REVA_AGENT_ID_MAP),
    tools: parseJsonObjectEnv(env.REVA_TOOL_ID_MAP),
    userGroups: parseJsonObjectEnv(env.REVA_USER_GROUPS_MAP)
  };
}

/**
 * Group memberships for a user, as a plain list of group ids.
 *
 * The Kong plugin reads these straight off a JWT claim (`cognito:groups` and friends) and
 * ships them as Cedar entity parents, which is what lets a policy say
 * `principal in UserGroup::"Underwriters"` instead of naming every user. We cannot do that
 * here: the bearer token on this webhook authenticates Power Platform, not the person, and
 * carries no claims about them at all — see the principal note in pdp.mjs. Copilot's body
 * gives us a user id and a tenant id and nothing else.
 *
 * So the source is configuration. Keyed by the RAW Microsoft id first (the Entra GUID, the
 * only stable handle) and then by the resolved Reva id, because whichever one the operator
 * already has in front of them is the one they will type.
 *
 * Unset means no groups, which means no `entities` block at all — the payload is then
 * byte-identical to what it was before this existed.
 */
export function resolveUserGroups(rawUserId, resolvedUserId, config) {
  const map = config?.userGroups || {};
  const lookup = (key) => {
    if (!key) return undefined;
    if (Object.prototype.hasOwnProperty.call(map, key)) return map[key];
    const lower = String(key).toLowerCase();
    const hit = Object.keys(map).find((k) => k.toLowerCase() === lower);
    return hit ? map[hit] : undefined;
  };

  const raw = lookup(rawUserId) ?? lookup(resolvedUserId);
  if (typeof raw === "string") return raw.trim() ? [raw.trim()] : [];
  if (!Array.isArray(raw)) return [];
  return [...new Set(raw.filter((g) => typeof g === "string" && g.trim()).map((g) => g.trim()))];
}

/**
 * Look a value up by id, then by name (both case-insensitively), then fall back to a slug
 * of the name. `via` records which rung answered so the caller can log or refuse.
 */
function resolve(map, { id, name, fallback }) {
  const lookup = (key) => {
    if (!key) return undefined;
    if (Object.prototype.hasOwnProperty.call(map, key)) return map[key];
    const lower = String(key).toLowerCase();
    const hit = Object.keys(map).find((k) => k.toLowerCase() === lower);
    return hit ? map[hit] : undefined;
  };

  const byId = lookup(id);
  if (typeof byId === "string" && byId.trim()) return { id: byId.trim(), via: "id-map", mapped: true };

  const byName = lookup(name);
  if (typeof byName === "string" && byName.trim()) return { id: byName.trim(), via: "name-map", mapped: true };

  const slug = slugify(name, slugify(id, fallback));
  return { id: slug, via: "slug", mapped: false };
}

export function resolveUser(rawUserId, config) {
  // Users are the one case with a real join key: User.externalId holds the Entra GUID.
  // Identity (pass the GUID straight through) is the correct fallback, not a slug — the
  // store may legitimately key users by their IdP subject.
  const map = config?.users || {};
  const direct = Object.prototype.hasOwnProperty.call(map, rawUserId) ? map[rawUserId] : undefined;
  if (typeof direct === "string" && direct.trim()) {
    return { id: direct.trim(), via: "id-map", mapped: true };
  }
  return { id: String(rawUserId || "unknown"), via: "passthrough", mapped: false };
}

export function resolveAgent(agent, config) {
  return resolve(config?.agents || {}, {
    id: agent?.id,
    name: agent?.name,
    fallback: "unknown-agent"
  });
}

export function resolveTool(toolDefinition, config) {
  return resolve(config?.tools || {}, {
    id: toolDefinition?.id,
    name: toolDefinition?.name,
    fallback: "unknown-tool"
  });
}

// REVA_ON_UNMAPPED_ENTITY and unmappedEntities() were removed here. They refused a request
// whose agent or tool resolved only by slug, on the premise that an unregistered id reaches
// the PDP as a non-existent entity and comes back as `403 authorization denied by policy`.
// pr06 answers 200 and evaluates it. The refusal was therefore blocking traffic the PDP
// would have allowed, and the header comment above records what changed.
