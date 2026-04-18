// index.ts — router principal admin-worker
// farpa Admin · Identity Provider · admin.farpa.ai
// Regras: ver CLAUDE.md raiz. Sem PII em logs. PKCE S256 obrigatório.
import type { Env } from "./env";
import { handleDiscovery } from "./discovery";
import { publicJwks } from "./jwks";
import { handleAuthorize } from "./authorize";
import { handleToken } from "./token";
import { handleUserinfo } from "./userinfo";
import { startGoogle, callbackGoogle, notImplemented } from "./social";
import { handleLocalLogin } from "./locallogin";
import { readSessionCookie, loadSession, revokeSession, clearSessionCookie } from "./session";
import { json, text, oauthError, handlePreflight, isAllowedOrigin } from "./util";

export default {
  async fetch(req: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    // CORS preflight (só endpoints cross-origin, não /oauth/authorize que é navegacional)
    const pre = handlePreflight(req, env);
    if (pre) return pre;

    const url = new URL(req.url);
    const p = url.pathname;
    const origin = req.headers.get("origin");

    try {
      // Health
      if (p === "/health") return text("ok\n");

      // OIDC discovery + JWKS
      if (p === "/.well-known/openid-configuration") return handleDiscovery(env);
      if (p === "/.well-known/jwks.json") {
        return json(publicJwks(env), { headers: { "cache-control": "public, max-age=600" } });
      }

      // OAuth2 core
      if (p === "/oauth/authorize" && req.method === "GET") return handleAuthorize(req, env);
      if (p === "/oauth/token" && req.method === "POST") {
        const resp = await handleToken(req, env);
        if (origin && isAllowedOrigin(env, origin)) {
          resp.headers.set("access-control-allow-origin", origin);
          resp.headers.set("access-control-allow-credentials", "true");
          resp.headers.set("vary", "origin");
        }
        return resp;
      }
      if (p === "/oauth/userinfo") return handleUserinfo(req, env);
      if (p === "/oauth/revoke" && req.method === "POST") return handleRevoke(req, env);
      if (p === "/oauth/logout") return handleLogout(req, env);

      // Local admin login
      if (p === "/login" && req.method === "POST") return handleLocalLogin(req, env);

      // Social start/callback
      if (p === "/oauth/google/start")    return startGoogle(req, env);
      if (p === "/oauth/google/callback") return callbackGoogle(req, env);
      if (p === "/oauth/apple/start" || p === "/oauth/apple/callback") return notImplemented("Apple");
      if (p === "/oauth/microsoft/start" || p === "/oauth/microsoft/callback") return notImplemented("Microsoft");

      // Admin interno (Fase 5C — protegido por sessão admin)
      if (p.startsWith("/admin/")) return handleAdmin(req, env, p);

      return oauthError("not_found", `No route for ${req.method} ${p}`, 404);
    } catch (err: any) {
      // Nunca vazar stack trace ou PII
      console.error("[admin-worker] unhandled", err?.message || err);
      return oauthError("server_error", "Internal error.", 500);
    }
  },
};

async function handleRevoke(req: Request, env: Env): Promise<Response> {
  const body = new URLSearchParams(await req.text());
  const token = body.get("token");
  if (!token) return oauthError("invalid_request", "Missing token.");
  const { sha256Hex } = await import("./util");
  const hash = await sha256Hex(token);
  await env.DB.prepare(`UPDATE refresh_tokens SET revoked_at = unixepoch() WHERE token_hash = ?`).bind(hash).run();
  return new Response(null, { status: 200 });
}

async function handleLogout(req: Request, env: Env): Promise<Response> {
  const sid = readSessionCookie(req);
  if (sid) await revokeSession(env, sid);
  const url = new URL(req.url);
  const returnTo = url.searchParams.get("post_logout_redirect_uri") || env.ISSUER;
  return new Response(null, {
    status: 302,
    headers: { location: returnTo, "set-cookie": clearSessionCookie() },
  });
}

/** Admin routes (Fase 5C) — apenas stubs com auth-gate por sessão. */
async function handleAdmin(req: Request, env: Env, path: string): Promise<Response> {
  const sid = readSessionCookie(req);
  const session = sid ? await loadSession(env, sid) : null;
  if (!session) return oauthError("unauthorized", "Login required.", 401);
  // TODO: enforce admin role check (nova coluna users.role = 'admin')

  if (path === "/admin/clients" && req.method === "GET") {
    const r = await env.DB.prepare(
      `SELECT client_id, name, redirect_uris, scopes, is_active, created_at FROM clients ORDER BY created_at DESC`
    ).all();
    return json({ clients: r.results });
  }
  if (path === "/admin/users" && req.method === "GET") {
    const r = await env.DB.prepare(
      `SELECT id, email, name, provider, last_login_at, created_at FROM users ORDER BY created_at DESC LIMIT 100`
    ).all();
    return json({ users: r.results });
  }
  return oauthError("not_found", `No admin route for ${req.method} ${path}`, 404);
}
