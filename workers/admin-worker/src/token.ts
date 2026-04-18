// token.ts — POST /oauth/token — exchange authorization_code → access_token + id_token + refresh_token
// Suporta grant_types: authorization_code, refresh_token
import type { Env } from "./env";
import { getClient, clientScopes, verifyClientSecret, extractClientCredentials } from "./clients";
import { signJwt, requireSigningKey } from "./jwks";
import { randomHex, sha256Hex, verifyPkceS256, json, oauthError } from "./util";

export async function handleToken(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") return oauthError("invalid_request", "POST required.", 405);
  const keyCheck = requireSigningKey(env);
  if (keyCheck) return keyCheck;

  const ct = req.headers.get("content-type") || "";
  if (!ct.includes("application/x-www-form-urlencoded")) {
    return oauthError("invalid_request", "Content-Type must be application/x-www-form-urlencoded.");
  }
  const body = new URLSearchParams(await req.text());
  const grantType = body.get("grant_type") || "";

  const creds = await extractClientCredentials(req, body);
  if (!creds) return oauthError("invalid_client", "Missing client credentials.", 401);
  const client = await getClient(env, creds.clientId);
  if (!client) return oauthError("invalid_client", "Unknown client.", 401);
  const ok = await verifyClientSecret(client.client_secret_hash, creds.clientSecret);
  if (!ok) return oauthError("invalid_client", "Bad client secret.", 401);

  if (grantType === "authorization_code") return exchangeCode(env, client.client_id, body);
  if (grantType === "refresh_token")      return exchangeRefresh(env, client.client_id, body);
  return oauthError("unsupported_grant_type", `Grant '${grantType}' not supported.`);
}

async function exchangeCode(env: Env, clientId: string, body: URLSearchParams): Promise<Response> {
  const code = body.get("code") || "";
  const redirectUri = body.get("redirect_uri") || "";
  const codeVerifier = body.get("code_verifier") || "";
  if (!code || !redirectUri || !codeVerifier) {
    return oauthError("invalid_request", "Missing code/redirect_uri/code_verifier.");
  }

  const row = await env.DB.prepare(
    `SELECT code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, expires_at, used_at
     FROM authorization_codes WHERE code = ?`
  ).bind(code).first<any>();
  if (!row) return oauthError("invalid_grant", "Unknown code.");
  if (row.client_id !== clientId) return oauthError("invalid_grant", "Code issued to different client.");
  if (row.redirect_uri !== redirectUri) return oauthError("invalid_grant", "redirect_uri mismatch.");
  if (row.used_at) {
    // Reuse de auth code → revogar toda a sessão associada (defesa em profundidade)
    await env.DB.prepare(`UPDATE sessions SET revoked_at = unixepoch() WHERE user_id = ?`).bind(row.user_id).run();
    return oauthError("invalid_grant", "Code already used.");
  }
  if (row.expires_at < Math.floor(Date.now() / 1000)) return oauthError("invalid_grant", "Code expired.");
  if (row.code_challenge_method !== "S256") return oauthError("invalid_grant", "Only S256 supported.");
  if (!(await verifyPkceS256(codeVerifier, row.code_challenge))) {
    return oauthError("invalid_grant", "PKCE verification failed.");
  }

  await env.DB.prepare(`UPDATE authorization_codes SET used_at = unixepoch() WHERE code = ?`).bind(code).run();

  const user = await env.DB.prepare(
    `SELECT id, email, email_verified, name, picture_url FROM users WHERE id = ?`
  ).bind(row.user_id).first<any>();
  if (!user) return oauthError("invalid_grant", "User not found.");

  const scopes: string[] = JSON.parse(row.scopes);
  return issueTokens(env, clientId, user, scopes, row.nonce || undefined);
}

async function exchangeRefresh(env: Env, clientId: string, body: URLSearchParams): Promise<Response> {
  const refreshToken = body.get("refresh_token") || "";
  if (!refreshToken) return oauthError("invalid_request", "Missing refresh_token.");
  const hash = await sha256Hex(refreshToken);
  const row = await env.DB.prepare(
    `SELECT id, token_hash, client_id, user_id, session_id, scopes, family_id, expires_at, revoked_at
     FROM refresh_tokens WHERE token_hash = ?`
  ).bind(hash).first<any>();
  if (!row) return oauthError("invalid_grant", "Unknown refresh_token.");
  if (row.client_id !== clientId) return oauthError("invalid_grant", "Token issued to different client.");
  if (row.expires_at < Math.floor(Date.now() / 1000)) return oauthError("invalid_grant", "Token expired.");
  if (row.revoked_at) {
    // Reuse detection — revoga family inteira
    await env.DB.prepare(`UPDATE refresh_tokens SET revoked_at = unixepoch() WHERE family_id = ?`).bind(row.family_id).run();
    return oauthError("invalid_grant", "Refresh token reuse detected; family revoked.");
  }

  // Rotação: revoga token atual e emite novo
  await env.DB.prepare(`UPDATE refresh_tokens SET revoked_at = unixepoch() WHERE id = ?`).bind(row.id).run();

  const user = await env.DB.prepare(
    `SELECT id, email, email_verified, name, picture_url FROM users WHERE id = ?`
  ).bind(row.user_id).first<any>();
  if (!user) return oauthError("invalid_grant", "User not found.");

  const scopes: string[] = JSON.parse(row.scopes);
  return issueTokens(env, clientId, user, scopes, undefined, row.family_id, row.id);
}

async function issueTokens(
  env: Env,
  clientId: string,
  user: { id: string; email: string; email_verified: number; name: string | null; picture_url: string | null },
  scopes: string[],
  nonce?: string,
  familyId?: string,
  parentId?: string
): Promise<Response> {
  const accessTtl = parseInt(env.ACCESS_TOKEN_TTL_SECONDS, 10);
  const refreshTtl = parseInt(env.REFRESH_TOKEN_TTL_SECONDS, 10);
  const includeOidc = scopes.includes("openid");
  const includeRefresh = scopes.includes("offline_access") || true; // default ON

  const accessToken = await signJwt(env, {
    sub: user.id, aud: clientId, scope: scopes.join(" "), token_use: "access",
  }, accessTtl);

  let idToken: string | undefined;
  if (includeOidc) {
    const claims: Record<string, unknown> = {
      sub: user.id, aud: clientId,
      email: user.email, email_verified: !!user.email_verified,
    };
    if (nonce) claims.nonce = nonce;
    if (scopes.includes("profile")) { claims.name = user.name; claims.picture = user.picture_url; }
    idToken = await signJwt(env, claims, accessTtl);
  }

  let refreshTokenOut: string | undefined;
  if (includeRefresh) {
    refreshTokenOut = randomHex(48);
    const rtHash = await sha256Hex(refreshTokenOut);
    const newId = randomHex(16);
    const newFamily = familyId || randomHex(16);
    const expiresAt = Math.floor(Date.now() / 1000) + refreshTtl;
    await env.DB.prepare(
      `INSERT INTO refresh_tokens (id, token_hash, client_id, user_id, scopes, family_id, parent_id, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(newId, rtHash, clientId, user.id, JSON.stringify(scopes), newFamily, parentId || null, expiresAt).run();
  }

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: accessTtl,
    scope: scopes.join(" "),
    ...(idToken ? { id_token: idToken } : {}),
    ...(refreshTokenOut ? { refresh_token: refreshTokenOut } : {}),
  });
}
