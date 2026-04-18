// locallogin.ts — POST /login (autenticação local para admin)
// Senha armazenada como PBKDF2-SHA256 no D1 (salt:hash base64).
// ADMIN_PASSWORD secret é usado apenas no primeiro login (bootstrap).
import type { Env } from "./env";
import { safeEqual } from "./util";
import { sessionCookie, createSession } from "./session";

const ADMIN_USER_ID = "00000000-0000-0000-0000-000000000001";

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100_000 }, key, 256
  );
  const b64 = (buf: ArrayBuffer | Uint8Array) =>
    btoa(String.fromCharCode(...(buf instanceof Uint8Array ? buf : new Uint8Array(buf))));
  return `${b64(salt)}:${b64(bits)}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(":");
  if (parts.length !== 2) return false;
  const salt = Uint8Array.from(atob(parts[0]), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100_000 }, key, 256
  );
  const newHash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return safeEqual(parts[1], newHash);
}

interface LocalUserRow {
  id: string;
  password_hash: string | null;
}

export async function handleLocalLogin(req: Request, env: Env): Promise<Response> {
  const body = new URLSearchParams(await req.text());
  const username = (body.get("username") || "").trim();
  const password = body.get("password") || "";
  const returnTo = body.get("return_to") || "/";

  const loginUrl = new URL("/login.html", env.ISSUER);
  if (returnTo && returnTo !== "/") loginUrl.searchParams.set("return_to", returnTo);

  const fail = () => {
    loginUrl.searchParams.set("error", "1");
    return Response.redirect(loginUrl.toString(), 302);
  };

  if (!username || !password) return fail();

  const adminUsername = env.ADMIN_USERNAME || "";
  if (!adminUsername || !safeEqual(username, adminUsername)) return fail();

  // Busca hash armazenado no D1
  const row = await env.DB.prepare(
    `SELECT id, password_hash FROM users WHERE provider = 'local' AND provider_sub = ? LIMIT 1`
  ).bind(username).first<LocalUserRow>();

  if (row?.password_hash) {
    // Usuário já existe — verifica hash do D1
    const ok = await verifyPassword(password, row.password_hash);
    if (!ok) return fail();
  } else {
    // Bootstrap: verifica contra ADMIN_PASSWORD secret e cria usuário com hash
    const adminPassword = env.ADMIN_PASSWORD || "";
    if (!adminPassword || !safeEqual(password, adminPassword)) return fail();

    const hash = await hashPassword(password);
    await env.DB.prepare(
      `INSERT OR REPLACE INTO users
         (id, email, email_verified, name, provider, provider_sub, password_hash, created_at)
       VALUES (?, ?, 1, 'Admin', 'local', ?, ?, unixepoch())`
    ).bind(ADMIN_USER_ID, `${username}@admin.farpa.ai`, username, hash).run();
  }

  const userId = row?.id ?? ADMIN_USER_ID;
  await env.DB.prepare(`UPDATE users SET last_login_at = unixepoch() WHERE id = ?`).bind(userId).run();

  const ua = req.headers.get("user-agent");
  const sid = await createSession(env, userId, ua);
  const ttl = parseInt(env.SESSION_TTL_SECONDS, 10);

  const safeReturn = returnTo.startsWith("/") ? returnTo : "/";
  return new Response(null, {
    status: 302,
    headers: {
      location: safeReturn,
      "set-cookie": sessionCookie(sid, ttl),
    },
  });
}
