import crypto from "node:crypto";

const CLOCK_SKEW_SECONDS = Number(process.env.JWT_CLOCK_SKEW_SECONDS || 60);
const JWKS_TTL_MS = Number(process.env.JWKS_CACHE_TTL_MS || 5 * 60 * 1000);

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + "=".repeat(padding), "base64");
}

export function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT.");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = JSON.parse(base64UrlDecode(encodedHeader).toString("utf8"));
  const payload = JSON.parse(base64UrlDecode(encodedPayload).toString("utf8"));
  const signature = base64UrlDecode(encodedSignature);

  return {
    encodedHeader,
    encodedPayload,
    encodedSignature,
    header,
    payload,
    signature,
    signingInput: `${encodedHeader}.${encodedPayload}`
  };
}

function normalizeAudience(audience) {
  if (!audience) return [];
  return Array.isArray(audience) ? audience : [audience];
}

function createIssuerCandidates(tenantId, explicitIssuer) {
  if (explicitIssuer) return [explicitIssuer];
  return [
    `https://login.microsoftonline.com/${tenantId}/v2.0`,
    `https://sts.windows.net/${tenantId}/`
  ];
}

function assertClaims(payload, config) {
  const now = Math.floor(Date.now() / 1000);
  const audiences = normalizeAudience(config.audience);
  const issuers = createIssuerCandidates(config.tenantId, config.issuer);

  if (!payload.iss || !issuers.includes(payload.iss)) {
    throw new Error("Token issuer is not allowed.");
  }

  if (!payload.tid || payload.tid !== config.tenantId) {
    throw new Error("Token tenant does not match the configured tenant.");
  }

  if (!payload.aud || !audiences.includes(payload.aud)) {
    throw new Error("Token audience is not allowed.");
  }

  if (typeof payload.exp !== "number" || payload.exp + CLOCK_SKEW_SECONDS < now) {
    throw new Error("Token is expired.");
  }

  if (typeof payload.nbf === "number" && payload.nbf - CLOCK_SKEW_SECONDS > now) {
    throw new Error("Token is not valid yet.");
  }

  // WHICH APPLICATION is calling, not merely which tenant. Everything above proves the
  // token came from the right tenant for the right audience — it does not prove Power
  // Platform sent it. Any application in the customer's tenant able to obtain a token for
  // this audience passes the checks above, and this webhook decides whether tool calls are
  // authorized, so "some app in the tenant" is not a good enough answer.
  //
  // Microsoft makes this the partner's job rather than the platform's:
  //   "you need to implement authorization logic and validate incoming tokens ... for
  //    example, using an allow list of app IDs, or role-based access control"
  //   — learn.microsoft.com/microsoft-copilot-studio/external-security-webhooks-interface-developers
  //
  // v1.0 tokens carry the caller in `appid`, v2.0 in `azp`. Unset means unenforced, because
  // we cannot ship a guessed GUID as a security control — see callerAppId on the
  // observability event for the value to put here.
  if (config.allowedAppIds && config.allowedAppIds.length > 0) {
    const caller = callerAppIdOf(payload);
    if (!caller) {
      throw new Error("Token carries no appid/azp claim, so the calling application cannot be authorized.");
    }
    if (!config.allowedAppIds.includes(caller.toLowerCase())) {
      throw new Error("Calling application is not in ENTRA_ALLOWED_APP_IDS.");
    }
  }
}

/** The application the token was issued to: `appid` on v1.0 tokens, `azp` on v2.0. */
export function callerAppIdOf(payload) {
  const raw = payload?.appid || payload?.azp || "";
  return typeof raw === "string" && raw.trim() ? raw.trim() : null;
}

function jwkToKeyObject(jwk) {
  return crypto.createPublicKey({
    key: jwk,
    format: "jwk"
  });
}

function verifySignature(parsedToken, jwk) {
  if (parsedToken.header.alg !== "RS256") {
    throw new Error(`Unsupported JWT alg "${parsedToken.header.alg}".`);
  }

  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(parsedToken.signingInput);
  verifier.end();

  const valid = verifier.verify(jwkToKeyObject(jwk), parsedToken.signature);
  if (!valid) {
    throw new Error("JWT signature verification failed.");
  }
}

async function fetchJwks(config, cache) {
  const now = Date.now();
  if (cache.keys && cache.expiresAt > now) {
    return cache.keys;
  }

  const response = await fetch(config.jwksUri, {
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS: ${response.status} ${response.statusText}`);
  }

  const body = await response.json();
  if (!body || !Array.isArray(body.keys)) {
    throw new Error("JWKS response did not contain a keys array.");
  }

  cache.keys = body.keys;
  cache.expiresAt = now + JWKS_TTL_MS;
  return cache.keys;
}

function findJwk(keys, kid) {
  return keys.find((key) => key.kid === kid && key.kty === "RSA" && key.use === "sig");
}

export function createAuth(options = {}) {
  const cache = {
    keys: null,
    expiresAt: 0
  };

  async function verifyEntraJwt(token) {
    const parsedToken = parseJwt(token);
    if (!parsedToken.header.kid) {
      throw new Error("JWT header is missing kid.");
    }

    const keys = options.jwks || (await fetchJwks(options, cache));
    const jwk = findJwk(keys, parsedToken.header.kid);
    if (!jwk) {
      throw new Error(`No signing key found for kid "${parsedToken.header.kid}".`);
    }

    verifySignature(parsedToken, jwk);
    assertClaims(parsedToken.payload, options);
    return parsedToken.payload;
  }

  async function authenticateBearerToken(token) {
    if (options.mode === "none") {
      return { ok: true, principal: null, authType: "none" };
    }

    if (!token) {
      return { ok: false, reason: "Missing bearer token." };
    }

    if (options.mode === "static") {
      if (token !== options.staticToken) {
        return { ok: false, reason: "Bearer token does not match the configured token." };
      }

      return { ok: true, principal: null, authType: "static" };
    }

    if (options.mode === "entra") {
      const principal = await verifyEntraJwt(token);
      // Recorded on every event even when the allowlist is empty: it is the only way to
      // learn the real Power Platform app id, and therefore the only way to populate
      // ENTRA_ALLOWED_APP_IDS from evidence rather than from a guess.
      return { ok: true, principal, authType: "entra", callerAppId: callerAppIdOf(principal) };
    }

    return { ok: false, reason: `Unsupported auth mode "${options.mode}".` };
  }

  return {
    authenticateBearerToken
  };
}

export function buildAuthConfigFromEnv(env = process.env) {
  const allowInsecure = env.ALLOW_INSECURE_LOCAL_AUTH === "true";
  const tenantId = env.ENTRA_TENANT_ID || "";
  const audience = env.ENTRA_AUDIENCE || "";
  const issuer = env.ENTRA_ISSUER || "";
  const jwksUri =
    env.ENTRA_JWKS_URI || (tenantId ? `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys` : "");
  const staticToken = env.AUTH_TOKEN || "";

  if (tenantId && audience) {
    return {
      mode: "entra",
      tenantId,
      audience,
      issuer,
      jwksUri,
      /**
       * Applications permitted to call this webhook, lower-cased for comparison. Empty
       * means unenforced — tenant + audience are then the only gate, which Microsoft
       * considers insufficient. See assertClaims().
       */
      allowedAppIds: String(env.ENTRA_ALLOWED_APP_IDS || "")
        .split(",")
        .map((id) => id.trim().toLowerCase())
        .filter(Boolean)
    };
  }

  if (allowInsecure) {
    if (staticToken) {
      return {
        mode: "static",
        staticToken
      };
    }

    return {
      mode: "none"
    };
  }

  throw new Error(
    "Authentication is not configured. Set ENTRA_TENANT_ID and ENTRA_AUDIENCE for production, or set ALLOW_INSECURE_LOCAL_AUTH=true for local development."
  );
}
