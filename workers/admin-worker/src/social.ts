// social.ts — callbacks de social login (Google / Apple / Microsoft)
// Fluxo: usuário clica "Continuar com Google" em /login.html →
//        /oauth/google/start?return_to=… (gera state+nonce, guarda em KV, redireciona p/ Google) →
//        Google volta em /oauth/google/callback?code=…&state=… →
//        troca code→tokens, upsert user, cria sessão, seta cookie admin_sid, redireciona p/ return_to
//
// Fase 5B.1: estrutura + start + callback Google.
// Apple e Microsoft seguem mesmo padrão (TODO).
import type { Env } from "./env";
import { randomHex, oauthError, sha256Hex } from "./util";
import { createSession, sessionCookie } from "./session";

const KV_STATE_PREFIX = "oauth_state:";
const STATE_TTL_SEC = 600; // 10 min

// ─── Google ──────────────────────────────────────────────────────────────────
export async function startGoogle(req: Request, env: Env): Promise<Response> {
  if (!env.GOOGLE_CLIENT_ID_IDP) return oauthError("server_error", "Google login not configured.", 503);
  const url = new URL(req.url);
  const returnTo = url.searchParams.get("return_to") || "/";
  const state = randomHex(16);
  const nonce = randomHex(16);
  await env.CACHE.put(
    KV_STATE_PREFIX + state,
    JSON.stringify({ provider: "google", returnTo, nonce }),
    { expirationTtl: STATE_TTL_SEC }
  );
  const redirectUri = `${env.ISSUER}/oauth/google/callback`;
  const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  auth.searchParams.set("client_id", env.GOOGLE_CLIENT_ID_IDP);
  auth.searchParams.set("redirect_uri", redirectUri);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "openid email profile");
  auth.searchParams.set("state", state);
  auth.searchParams.set("nonce", nonce);
  auth.searchParams.set("access_type", "online");
  auth.searchParams.set("prompt", "select_account");
  return Response.redirect(auth.toString(), 302);
}

export async function callbackGoogle(req: Request, env: Env): Promise<Response> {
  if (!env.GOOGLE_CLIENT_ID_IDP || !env.GOOGLE_CLIENT_SECRET_IDP) {
    return oauthError("server_error", "Google login not configured.", 503);
  }
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return oauthError("invalid_request", "Missing code/state.", 400);

  const savedRaw = await env.CACHE.get(KV_STATE_PREFIX + state);
  if (!savedRaw) return oauthError("invalid_request", "State expired or unknown.", 400);
  await env.CACHE.delete(KV_STATE_PREFIX + state);
  const saved = JSON.parse(savedRaw) as { provider: string; returnTo: string; nonce: string };

  const redirectUri = `${env.ISSUER}/oauth/google/callback`;
  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID_IDP,
      client_secret: env.GOOGLE_CLIENT_SECRET_IDP,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }).toString(),
  });
  if (!tokenResp.ok) return oauthError("invalid_grant", "Google token exchange failed.", 502);
  const tokens = await tokenResp.json() as { access_token: string; id_token?: string };

  const uiResp = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  if (!uiResp.ok) return oauthError("invalid_grant", "Google userinfo failed.", 502);
  const gu = await uiResp.json() as {
    sub: string; email: string; email_verified: boolean;
    name?: string; picture?: string;
  };

  // Upsert user
  const existing = await env.DB.prepare(
    `SELECT id FROM users WHERE provider = 'google' AND provider_sub = ?`
  ).bind(gu.sub).first<{ id: string }>();
  let userId: string;
  if (existing) {
    userId = existing.id;
    await env.DB.prepare(
      `UPDATE users SET email=?, email_verified=?, name=?, picture_url=?, last_login_at=unixepoch() WHERE id=?`
    ).bind(gu.email, gu.email_verified ? 1 : 0, gu.name || null, gu.picture || null, userId).run();
  } else {
    userId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO users (id, email, email_verified, name, picture_url, provider, provider_sub, last_login_at)
       VALUES (?, ?, ?, ?, ?, 'google', ?, unixepoch())`
    ).bind(userId, gu.email, gu.email_verified ? 1 : 0, gu.name || null, gu.picture || null, gu.sub).run();
  }

  // Sessão + cookie SameSite=None; Partitioned
  const sid = await createSession(env, userId, req.headers.get("user-agent"));
  const cookie = sessionCookie(sid, parseInt(env.SESSION_TTL_SECONDS, 10));

  // Audit (sem PII)
  await env.DB.prepare(
    `INSERT INTO audit_log (event, user_id, details) VALUES ('login.ok', ?, ?)`
  ).bind(userId, JSON.stringify({ provider: "google", nonce_hash: (await sha256Hex(saved.nonce)).slice(0, 16) })).run();

  const safeReturnTo = isSafeReturnTo(saved.returnTo) ? saved.returnTo : "/";
  return new Response(null, {
    status: 302,
    headers: { location: safeReturnTo, "set-cookie": cookie },
  });
}

// ─── Apple & Microsoft ───────────────────────────────────────────────────────
// TODO Fase 5B.2: replicar padrão de Google.
// Apple usa form_post (response_mode=form_post) + client_secret JWT (ES256 sob Services ID).
// Microsoft usa v2.0 endpoint + tenant=common.
export async function notImplemented(provider: string): Promise<Response> {
  return oauthError("temporarily_unavailable", `${provider} login scaffold — pending Fase 5B.2.`, 503);
}

// ─── Guard de return_to (anti open-redirect) ─────────────────────────────────
function isSafeReturnTo(ret: string): boolean {
  if (ret.startsWith("/")) return true; // same-origin relativo
  // allowlist de subdomínios farpa.ai
  try {
    const u = new URL(ret);
    return /\.farpa\.ai$/.test(u.hostname) || u.hostname === "farpa.ai";
  } catch {
    return false;
  }
}
