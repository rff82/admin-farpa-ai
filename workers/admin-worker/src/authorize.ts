// authorize.ts — GET /oauth/authorize (OAuth 2.1 + OIDC + PKCE)
// Fluxo:
//  1. Valida client_id, redirect_uri (match exato), scope, response_type=code, code_challenge, state
//  2. Se usuário não tem sessão → redireciona para /login (interno) com return_to
//  3. Se tem sessão → cria authorization_code (TTL 60s) e redireciona para redirect_uri
//     com ?code=<code>&state=<state>
import type { Env } from "./env";
import { getClient, clientRedirectUris, clientScopes } from "./clients";
import { readSessionCookie, loadSession } from "./session";
import { randomHex, oauthError } from "./util";

export async function handleAuthorize(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const p = url.searchParams;

  // Parâmetros obrigatórios OAuth/OIDC
  const clientId             = p.get("client_id") || "";
  const redirectUri          = p.get("redirect_uri") || "";
  const responseType         = p.get("response_type") || "";
  const scope                = p.get("scope") || "";
  const state                = p.get("state") || "";
  const codeChallenge        = p.get("code_challenge") || "";
  const codeChallengeMethod  = p.get("code_challenge_method") || "S256";
  const nonce                = p.get("nonce") || "";

  // Validações protegidas: erros NUNCA redirecionam se client_id/redirect_uri inválidos
  // (RFC 6749 §4.1.2.1) — evita open redirector.
  const client = await getClient(env, clientId);
  if (!client) return oauthError("invalid_request", "Unknown client_id.", 400);

  const allowedUris = clientRedirectUris(client);
  if (!allowedUris.includes(redirectUri)) {
    return oauthError("invalid_request", "redirect_uri not registered (exact match required).", 400);
  }

  // A partir daqui erros redirecionam para redirect_uri com ?error=…&state=…
  const errRedirect = (error: string, description: string) => {
    const u = new URL(redirectUri);
    u.searchParams.set("error", error);
    u.searchParams.set("error_description", description);
    if (state) u.searchParams.set("state", state);
    return Response.redirect(u.toString(), 302);
  };

  if (responseType !== "code") return errRedirect("unsupported_response_type", "Only 'code' is supported.");
  if (client.require_pkce && (!codeChallenge || codeChallengeMethod !== "S256")) {
    return errRedirect("invalid_request", "PKCE with S256 is required.");
  }

  // Valida escopos solicitados ⊆ escopos permitidos do client
  const requested = scope.split(/\s+/).filter(Boolean);
  const allowed = new Set(clientScopes(client));
  for (const s of requested) if (!allowed.has(s)) {
    return errRedirect("invalid_scope", `Scope '${s}' not allowed for this client.`);
  }

  // Sessão do usuário
  const sid = readSessionCookie(req);
  const session = sid ? await loadSession(env, sid) : null;
  if (!session) {
    // Redireciona para login com return_to
    const loginUrl = new URL("/login.html", env.ISSUER);
    loginUrl.searchParams.set("return_to", url.pathname + url.search);
    return Response.redirect(loginUrl.toString(), 302);
  }

  // Emite authorization_code TTL curto
  const code = randomHex(32);
  const ttl = parseInt(env.AUTH_CODE_TTL_SECONDS, 10);
  const expiresAt = Math.floor(Date.now() / 1000) + ttl;
  await env.DB.prepare(
    `INSERT INTO authorization_codes
     (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, state, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    code, clientId, session.user_id, redirectUri,
    JSON.stringify(requested), codeChallenge, codeChallengeMethod,
    nonce || null, state || null, expiresAt
  ).run();

  const out = new URL(redirectUri);
  out.searchParams.set("code", code);
  if (state) out.searchParams.set("state", state);
  return Response.redirect(out.toString(), 302);
}
