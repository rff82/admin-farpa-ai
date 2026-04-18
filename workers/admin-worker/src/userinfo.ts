// userinfo.ts — GET /oauth/userinfo (OIDC Core 1.0 §5.3)
// Valida Bearer token (assinatura + exp + iss) e retorna claims.
import type { Env } from "./env";
import { json, oauthError, base64url } from "./util";

export async function handleUserinfo(req: Request, env: Env): Promise<Response> {
  const auth = req.headers.get("authorization") || "";
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return new Response(null, { status: 401, headers: { "www-authenticate": 'Bearer realm="farpa"' }});
  }
  const token = auth.slice(7).trim();
  const parts = token.split(".");
  if (parts.length !== 3) return oauthError("invalid_token", "Malformed JWT.", 401);

  // Parse + valida assinatura contra JWT_SIGNING_KEY_CURRENT (e PREVIOUS durante rotação)
  const valid = await verifyJwtEs256(env, parts[0], parts[1], parts[2]);
  if (!valid) return oauthError("invalid_token", "Signature/claims invalid.", 401);

  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  if (payload.iss !== env.ISSUER) return oauthError("invalid_token", "Bad issuer.", 401);
  if (payload.exp < Math.floor(Date.now() / 1000)) return oauthError("invalid_token", "Expired.", 401);

  const row = await env.DB.prepare(
    `SELECT id, email, email_verified, name, picture_url FROM users WHERE id = ?`
  ).bind(payload.sub).first<any>();
  if (!row) return oauthError("invalid_token", "Unknown subject.", 401);

  const scopes = String(payload.scope || "").split(/\s+/).filter(Boolean);
  const out: Record<string, unknown> = { sub: row.id };
  if (scopes.includes("email"))   { out.email = row.email; out.email_verified = !!row.email_verified; }
  if (scopes.includes("profile")) { out.name = row.name; out.picture = row.picture_url; }
  return json(out);
}

function b64urlDecode(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyJwtEs256(env: Env, h: string, p: string, sig: string): Promise<boolean> {
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h)));
  if (header.alg !== "ES256") return false;
  const candidates = [env.JWT_SIGNING_KEY_CURRENT, env.JWT_SIGNING_KEY_PREVIOUS].filter(Boolean) as string[];
  for (const raw of candidates) {
    try {
      const jwk = JSON.parse(raw);
      if (header.kid && jwk.kid && header.kid !== jwk.kid) continue;
      const pub = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
      const key = await crypto.subtle.importKey("jwk", pub, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        b64urlDecode(sig),
        new TextEncoder().encode(`${h}.${p}`)
      );
      if (ok) return true;
    } catch {}
  }
  return false;
}
