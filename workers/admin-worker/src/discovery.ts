// discovery.ts — OIDC Discovery metadata
// Servido em /.well-known/openid-configuration (RFC 8414 + OIDC Discovery 1.0)
import type { Env } from "./env";
import { json } from "./util";

export function discoveryMetadata(env: Env) {
  const iss = env.ISSUER;
  return {
    issuer: iss,
    authorization_endpoint: `${iss}/oauth/authorize`,
    token_endpoint: `${iss}/oauth/token`,
    userinfo_endpoint: `${iss}/oauth/userinfo`,
    revocation_endpoint: `${iss}/oauth/revoke`,
    end_session_endpoint: `${iss}/oauth/logout`,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "picture"],
    service_documentation: "https://admin.farpa.ai",
    ui_locales_supported: ["pt-BR", "en"],
  };
}

export function handleDiscovery(env: Env): Response {
  return json(discoveryMetadata(env), {
    headers: { "cache-control": "public, max-age=3600" },
  });
}
