// jwks.ts — gestão de chaves JWT + assinatura de id_token/access_token
// Formato de JWT: JWS compacto (header.payload.signature), algoritmo ES256 (EC P-256).
// Chaves privadas vêm de env.JWT_SIGNING_KEY_CURRENT (JWK JSON string) via wrangler secret.
// Fase 5B.1: suporta só chave current. Fase 5B.2 adiciona rotação (previous + múltiplos kid no JWKS público).
import type { Env } from "./env";
import { base64url, oauthError } from "./util";

interface JwkPrivate {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d: string;
  kid: string;
  alg?: "ES256";
  use?: "sig";
}

interface JwkPublic {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  kid: string;
  alg: "ES256";
  use: "sig";
}

function parsePrivateJwk(raw: string | undefined, label: string): JwkPrivate {
  if (!raw) throw new Error(`missing_key:${label}`);
  const jwk = JSON.parse(raw) as JwkPrivate;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d || !jwk.kid) {
    throw new Error(`invalid_jwk:${label}`);
  }
  return jwk;
}

function toPublic(jwk: JwkPrivate): JwkPublic {
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid: jwk.kid, alg: "ES256", use: "sig" };
}

/** Importa chave JWK privada como CryptoKey para assinatura. */
async function importSigningKey(jwk: JwkPrivate): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

/** Retorna JWKS público (RFC 7517) para `/.well-known/jwks.json`. */
export function publicJwks(env: Env): { keys: JwkPublic[] } {
  const keys: JwkPublic[] = [];
  try { keys.push(toPublic(parsePrivateJwk(env.JWT_SIGNING_KEY_CURRENT, "current"))); } catch {}
  try { keys.push(toPublic(parsePrivateJwk(env.JWT_SIGNING_KEY_PREVIOUS, "previous"))); } catch {}
  return { keys };
}

/** Assina payload como JWT compacto ES256. */
export async function signJwt(env: Env, payload: Record<string, unknown>, expiresInSec: number): Promise<string> {
  const jwk = parsePrivateJwk(env.JWT_SIGNING_KEY_CURRENT, "current");
  const key = await importSigningKey(jwk);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: jwk.kid };
  const fullPayload = { iat: now, exp: now + expiresInSec, iss: env.ISSUER, ...payload };
  const headerB64 = base64url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64url(new TextEncoder().encode(JSON.stringify(fullPayload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput)
  );
  const sigB64 = base64url(sig);
  return `${signingInput}.${sigB64}`;
}

/** Erro útil para expor quando faltam secrets. */
export function requireSigningKey(env: Env): Response | null {
  try {
    parsePrivateJwk(env.JWT_SIGNING_KEY_CURRENT, "current");
    return null;
  } catch (err) {
    return oauthError(
      "server_error",
      "IdP signing key not configured. Run: wrangler secret put JWT_SIGNING_KEY_CURRENT",
      503
    );
  }
}
