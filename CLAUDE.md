# CLAUDE.md — farpa Admin
> Arquivo de contexto automático · rff82/admin-farpa-ai · v0.1 · 2026-04-18

---

## IDENTIDADE DO PRODUTO

**admin.farpa.ai** é o **Identity Provider (IdP) centralizado + Console do Ecossistema** farpa. Duas faces da mesma plataforma:

1. **Console (público/interno)** — painel que lista todos os produtos do ecossistema com status, acesso rápido, métricas. Consome `/data/products.json` (sincronizado de `farpa-reengenharia/09-configuracao/ecosystem.yaml`).
2. **IdP OAuth2 + OIDC (backend)** — autenticação, autorização e recuperação de conta para todos os produtos (farpa.ai, labs, health, fintech, forte, library…). Social login Google/Apple/Microsoft. PKCE obrigatório.

> Nenhum produto implementa auth próprio — todos delegam para `admin.farpa.ai`.

**Categoria de mercado:** IdP/SaaS B2B interno.
**Benchmarks:** Auth0, Clerk, WorkOS, Supabase Auth, Cloudflare Access.

---

## DESIGN SYSTEM — exceção legítima ao "paleta por categoria"

Por regra mestre (`farpa-reengenharia/02-design-system/05-trend-research.md`), admin é o ÚNICO produto que usa o **índigo mestre farpa `#4338CA`** como primary. Outros produtos usam primary on-trend da sua categoria; admin carrega a identidade mestre porque representa o ecossistema inteiro.

```
Primary:       #4338CA  (índigo mestre farpa)
Primary high:  #6D5DF3
Bg base:       #0B0B12  (near-black neutro)
Bg elevado:    #13131E
Tipografia:    Plus Jakarta Sans + JetBrains Mono (imutáveis)
Tema padrão:   Dark cinematic executivo
Alto contraste: #btn-alto-contraste → .theme-alto-contraste (WCAG AAA, amarelo #FFFF00)
```

Ordem de carregamento:
```html
<link rel="stylesheet" href="tokens.css">
<link rel="stylesheet" href="themes.css">
<link rel="stylesheet" href="logo-system.css">
<link rel="stylesheet" href="admin.css">
<script src="icons.js"></script>
```

---

## ESTRUTURA DO REPOSITÓRIO

```
/
├── index.html              ← Console do Ecossistema (público)
├── login.html              ← Stub OAuth social (Fase 5B ativa Worker)
├── admin.css               ← CSS específico — NÃO sync
├── tokens.css              ← sync com ../shared/
├── themes.css              ← sync com ../shared/
├── logo-system.css         ← sync com ../shared/
├── icons.js                ← sync com ../shared/
├── data/products.json      ← gerado de ecosystem.yaml (carrossel + console)
├── .github/workflows/ci.yml
├── workers/admin-worker/   ← [Fase 5B] Worker OAuth2/OIDC
├── schema.sql              ← [Fase 5B] D1 — users/clients/sessions/codes
└── CLAUDE.md
```

> ⚠️ `tokens.css` / `themes.css` / `logo-system.css` / `icons.js` → copiar de `../shared/` e não editar.

---

## INFRAESTRUTURA

```
Repositório:   github.com/rff82/admin-farpa-ai (branch main)
Pages project: farpa-admin
Subdomínio:    admin.farpa.ai → CNAME farpa-admin.pages.dev
Worker:        admin-farpa-ai (Fase 5B)
D1:            admin-farpa-ai-db (Fase 5B) · tabelas: users, clients, sessions, authorization_codes
KV:            ADMIN_CACHE (Fase 5B) · JWKS, tokens de curto prazo, state/nonce
```

---

## ROADMAP FASEADO

### Fase 5A — ATUAL: Console público (scaffold v0.1)
- [x] Repo GitHub + CI self-healing
- [x] `index.html` Console consumindo `/data/products.json`
- [x] `login.html` stub com social buttons desabilitados
- [x] Design system neutro executivo (índigo mestre)
- [ ] Deploy Cloudflare Pages (DNS `admin.farpa.ai`)

### Fase 5B — IdP OAuth2/OIDC (pendente confirmação)
- [ ] `wrangler d1 create admin-farpa-ai-db` + schema
- [ ] `wrangler kv namespace create ADMIN_CACHE`
- [ ] Worker `admin-worker` com rotas `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`
- [ ] `/.well-known/openid-configuration` + `/.well-known/jwks.json`
- [ ] Social login callbacks (Google, Apple, Microsoft)
- [ ] Secrets: `GOOGLE_CLIENT_ID_IDP`, `GOOGLE_CLIENT_SECRET_IDP`, `JWT_SIGNING_KEY_*`, `SESSION_COOKIE_SECRET`

### Fase 5C — Admin interno
- [ ] `/admin/clients` (listar/criar client_id por produto)
- [ ] `/admin/users` (paginado, filtros)
- [ ] Dashboard de sessões ativas + revogação

---

## REGRAS INEGOCIÁVEIS (herdadas do mestre)

- **Alto contraste é toggle SECUNDÁRIO** — `#btn-alto-contraste` no header. Tema padrão é dark cinematic índigo. Não inverter.
- **Auth cross-site**: cookie de sessão `admin_sid` emitido como `HttpOnly; Secure; SameSite=None; Partitioned; Path=/`. `SameSite=Lax` quebra login entre produtos (incidente Forte 2026-04-18).
- **PKCE obrigatório** (`code_challenge_method=S256`) para todos os clients — inclusive confidential.
- **API keys nunca no cliente** — sempre `wrangler secret put`.
- **client_secret nunca em claro** — hash com argon2/bcrypt em `clients.client_secret_hash`.
- **redirect_uri** com match exato, sem wildcards.
- **state + nonce** obrigatórios em todos os fluxos OAuth (CSRF + replay protection).
- **Rate limit** 10 req/min por IP em `/oauth/token`.
- **Logs sem PII** — nunca logar email, tokens ou client_secret; só IDs opacos.
- **Tipografia imutável** — Plus Jakarta Sans + JetBrains Mono.
- **Cores nunca hardcoded** — sempre `var(--admin-xxx)` ou `var(--token)`.
- **Ícones SVG line (Lucide)** via `<span data-icon="nome"></span>` + `icons.js`. Nunca emojis em UI funcional.
- **Logo unificado** — `<a class="farpa-logo">` + `.farpa-logo-mark` com `--logo-mark-bg: var(--admin-primary)`. Nunca SVG próprio.
- **CI self-healing** — falhas viram entrada em `## HISTÓRICO DE FALHAS DE CI` + issue `ci-failure`.
- **Cloudflare Free Tier** — 100k Worker req/dia, D1 5M reads/100k writes, KV 100k reads.

---

## COMANDOS DE PROVISIONAMENTO (Fase 5B)

```bash
# Banco D1
npx wrangler d1 create admin-farpa-ai-db
# → copiar database_id para workers/admin-worker/wrangler.jsonc

# KV
npx wrangler kv namespace create ADMIN_CACHE
# → copiar id para workers/admin-worker/wrangler.jsonc

# Schema
npx wrangler d1 execute admin-farpa-ai-db --file ./schema.sql --remote

# Secrets
cd workers/admin-worker
npx wrangler secret put GOOGLE_CLIENT_ID_IDP
npx wrangler secret put GOOGLE_CLIENT_SECRET_IDP
npx wrangler secret put APPLE_CLIENT_ID_IDP
npx wrangler secret put APPLE_CLIENT_SECRET_IDP
npx wrangler secret put MICROSOFT_CLIENT_ID_IDP
npx wrangler secret put MICROSOFT_CLIENT_SECRET_IDP
npx wrangler secret put JWT_SIGNING_KEY_CURRENT   # openssl rand -base64 64
npx wrangler secret put SESSION_COOKIE_SECRET     # openssl rand -base64 48
npx wrangler secret put ALLOWED_ORIGIN            # https://admin.farpa.ai
npx wrangler secret put ADMIN_USERNAME            # nicole-usr
npx wrangler secret put ADMIN_PASSWORD            # nicole-pws (usado só no 1º login — depois hash fica no D1)

npx wrangler deploy
```

---

## FLUXO PADRÃO

```
Editar → commit → push main → CI GitHub Actions → CF Pages (Worker na Fase 5B) ~2 min
```

---

*farpa Admin · CLAUDE.md · v0.1 · 2026-04-18 · Cloudflare-first · OAuth 2.1 Best Practices*
