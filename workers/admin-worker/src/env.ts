// env.ts — tipo de bindings do Worker
export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;

  // Vars
  ISSUER: string;
  ALLOWED_ORIGINS: string;
  SESSION_TTL_SECONDS: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_SECONDS: string;
  AUTH_CODE_TTL_SECONDS: string;

  // Secrets (wrangler secret put)
  SESSION_COOKIE_SECRET: string;          // HMAC do cookie
  JWT_SIGNING_KEY_CURRENT?: string;       // JWK JSON (EC P-256 ou RSA) — emissão atual
  JWT_SIGNING_KEY_PREVIOUS?: string;      // JWK JSON — validação durante rotação

  GOOGLE_CLIENT_ID_IDP?: string;
  GOOGLE_CLIENT_SECRET_IDP?: string;
  APPLE_CLIENT_ID_IDP?: string;
  APPLE_CLIENT_SECRET_IDP?: string;
  MICROSOFT_CLIENT_ID_IDP?: string;
  MICROSOFT_CLIENT_SECRET_IDP?: string;
}
