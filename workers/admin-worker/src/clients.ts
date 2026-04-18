// clients.ts — leitura + validação de clients OAuth
import type { Env } from "./env";
import { safeEqual, sha256Hex } from "./util";

export interface ClientRow {
  client_id: string;
  client_secret_hash: string;
  name: string;
  redirect_uris: string; // JSON array
  scopes: string;        // JSON array
  grant_types: string;
  token_endpoint_auth_method: string;
  require_pkce: number;
  is_active: number;
}

export async function getClient(env: Env, clientId: string): Promise<ClientRow | null> {
  if (!clientId) return null;
  const row = await env.DB.prepare(
    `SELECT * FROM clients WHERE client_id = ? AND is_active = 1`
  ).bind(clientId).first<ClientRow>();
  return row || null;
}

export function clientRedirectUris(c: ClientRow): string[] {
  try { return JSON.parse(c.redirect_uris); } catch { return []; }
}
export function clientScopes(c: ClientRow): string[] {
  try { return JSON.parse(c.scopes); } catch { return []; }
}

/** Hash de client_secret usando SHA-256 + salt opaco (armazenado no próprio hash).
 *  Formato: "sha256$<hex-salt>$<hex-digest>".
 *  NOTE: em produção idealmente argon2id via WebCrypto indisponível — Workers não tem argon2
 *  nativo, então usamos SHA-256 com salt de 16 bytes (aceitável para secrets de 32+ bytes gerados aleatoriamente,
 *  como é o caso de client_secret emitidos pelo próprio IdP). Cliente humano nunca digita secret. */
export async function hashClientSecret(secret: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
  const digest = await sha256Hex(saltHex + ":" + secret);
  return `sha256$${saltHex}$${digest}`;
}

export async function verifyClientSecret(hash: string, secret: string): Promise<boolean> {
  const parts = hash.split("$");
  if (parts.length !== 3 || parts[0] !== "sha256") return false;
  const saltHex = parts[1];
  const expected = parts[2];
  const digest = await sha256Hex(saltHex + ":" + secret);
  return safeEqual(digest, expected);
}

/** Parse `Authorization: Basic base64(client_id:client_secret)` ou body form. */
export async function extractClientCredentials(
  req: Request,
  formBody: URLSearchParams
): Promise<{ clientId: string; clientSecret: string } | null> {
  const auth = req.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("basic ")) {
    try {
      const decoded = atob(auth.slice(6).trim());
      const idx = decoded.indexOf(":");
      if (idx > 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, idx)),
          clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
        };
      }
    } catch {}
  }
  const cid = formBody.get("client_id");
  const cs = formBody.get("client_secret");
  if (cid && cs) return { clientId: cid, clientSecret: cs };
  return null;
}
