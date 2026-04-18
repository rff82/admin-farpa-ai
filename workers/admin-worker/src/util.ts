// util.ts — helpers comuns
import type { Env } from "./env";

/** JSON response com CORS adequado (cross-origin OAuth endpoints). */
export function json(body: unknown, init: ResponseInit = {}, origin?: string): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("pragma", "no-cache");
  if (origin) applyCors(headers, origin);
  return new Response(JSON.stringify(body), { ...init, headers });
}

export function text(body: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) headers.set("content-type", "text/plain; charset=utf-8");
  return new Response(body, { ...init, headers });
}

/** Aplica CORS restrito a origens autorizadas (whitelist em ALLOWED_ORIGINS). */
export function applyCors(headers: Headers, origin: string) {
  headers.set("access-control-allow-origin", origin);
  headers.set("vary", "origin");
  headers.set("access-control-allow-credentials", "true");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "authorization,content-type");
}

export function isAllowedOrigin(env: Env, origin: string | null): boolean {
  if (!origin) return false;
  const allowed = env.ALLOWED_ORIGINS.split(",").map((s) => s.trim());
  return allowed.includes(origin);
}

export function handlePreflight(req: Request, env: Env): Response | null {
  if (req.method !== "OPTIONS") return null;
  const origin = req.headers.get("origin");
  if (!isAllowedOrigin(env, origin)) return new Response(null, { status: 403 });
  const headers = new Headers();
  applyCors(headers, origin!);
  headers.set("access-control-max-age", "86400");
  return new Response(null, { status: 204, headers });
}

/** Random hex token (N bytes). */
export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 hex. */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Base64URL encode (sem padding). */
export function base64url(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/** Verifica PKCE code_verifier (RFC 7636 §4.6 · S256 apenas). */
export async function verifyPkceS256(verifier: string, challenge: string): Promise<boolean> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(hash) === challenge;
}

/** Constant-time compare (timing-attack safe). */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Error response padrão OAuth2 (RFC 6749 §5.2). */
export function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, { status });
}

/** Extrai IP do header CF-Connecting-IP + hash para log. */
export async function ipHash(req: Request): Promise<string> {
  const ip = req.headers.get("cf-connecting-ip") || "";
  return (await sha256Hex(ip + ":farpa-admin")).slice(0, 24);
}
