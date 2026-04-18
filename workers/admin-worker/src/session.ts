// session.ts — cookie admin_sid · SameSite=None; Secure; Partitioned (CHIPS)
// Regra mestre: farpa-reengenharia/03-arquitetura/02-fluxos-e-apis.md
import type { Env } from "./env";
import { randomHex, sha256Hex } from "./util";

const COOKIE_NAME = "admin_sid";

export interface SessionRow {
  id: string;
  user_id: string;
  expires_at: number;
  revoked_at: number | null;
}

/** Serializa cookie de sessão. SameSite=None obrigatório para cross-site (Pages ↔ Worker de outros subdomínios). */
export function sessionCookie(value: string, maxAgeSec: number): string {
  return [
    `${COOKIE_NAME}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Partitioned",
    `Max-Age=${maxAgeSec}`,
  ].join("; ");
}

/** Cookie de remoção (logout). */
export function clearSessionCookie(): string {
  return sessionCookie("", 0);
}

export function readSessionCookie(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return m ? m[1] : null;
}

/** Cria sessão em D1 + retorna id opaco. */
export async function createSession(env: Env, userId: string, userAgent: string | null): Promise<string> {
  const id = randomHex(32);
  const ttl = parseInt(env.SESSION_TTL_SECONDS, 10);
  const expiresAt = Math.floor(Date.now() / 1000) + ttl;
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, user_agent, expires_at) VALUES (?, ?, ?, ?)`
  ).bind(id, userId, (userAgent || "").slice(0, 200), expiresAt).run();
  return id;
}

export async function loadSession(env: Env, sid: string): Promise<SessionRow | null> {
  if (!sid) return null;
  const row = await env.DB.prepare(
    `SELECT id, user_id, expires_at, revoked_at FROM sessions WHERE id = ?`
  ).bind(sid).first<SessionRow>();
  if (!row) return null;
  if (row.revoked_at) return null;
  if (row.expires_at < Math.floor(Date.now() / 1000)) return null;
  return row;
}

export async function revokeSession(env: Env, sid: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE sessions SET revoked_at = unixepoch() WHERE id = ?`
  ).bind(sid).run();
}
