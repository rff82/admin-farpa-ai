# admin-farpa-ai

**admin.farpa.ai** — Identity Provider (IdP) centralizado + Console do Ecossistema farpa.

- **Console** público que lista todos os produtos do ecossistema com status e acesso rápido.
- **IdP OAuth2 + OIDC** (Fase 5B) — autenticação única para farpa.ai, labs, health, fintech, forte, library…

Stack: Cloudflare Pages + Workers + D1 + KV. Design system: índigo mestre `#4338CA` + Plus Jakarta Sans.

Ver [`CLAUDE.md`](CLAUDE.md) para roadmap, regras e provisionamento.

## Deploy

```
git push origin main  # CI dispara wrangler pages deploy → admin.farpa.ai
```

## Licença

Proprietário · ecossistema farpa.ai · Rodrigo (rff82)
