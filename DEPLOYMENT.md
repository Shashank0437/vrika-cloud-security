# vrika-cloud-security — Deployment Guide

Steps to deploy the full stack (API, worker, worker-beat, UI, Postgres, Valkey,
Neo4j, MCP server, nginx) to a fresh server.

- Repo: https://github.com/Shashank0437/vrika-cloud-security
- Compose files: `docker-compose.yml` + `docker-compose.vrika.yml` (overlay)
- Local images built on the host: `prowlercloud/prowler-api:local`, `vrika-prowler-ui:local`
- Stack nginx publishes host port **8090** (plain HTTP). TLS is handled by a
  separate host-level nginx if you need HTTPS.

Replace `<HOST>` below with the server IP or domain (e.g. `10.239.37.110`).

---

## 1. Prerequisites (on the new server)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git
sudo usermod -aG docker "$USER"      # then log out/in for group to apply
docker --version && docker compose version
```

Ensure host port **8090** is free (`ss -tlnp | grep 8090`). If you add a
host-level nginx for TLS, also free 80/443.

## 2. Clone the repo

```bash
cd ~
git clone https://github.com/Shashank0437/vrika-cloud-security.git
cd vrika-cloud-security
git checkout main
```

## 3. Create and edit `.env`

```bash
cp .env.vrika.example .env
```

Edit `.env` — replace every `192.168.9.188` with `<HOST>` and set real secrets:

| Variable | Value |
|----------|-------|
| `AUTH_URL` | `https://<HOST>/prowler` |
| `UI_API_BASE_URL` | `https://<HOST>/prowler/api/v1` |
| `NEXT_PUBLIC_API_BASE_URL` | `https://<HOST>/prowler/api/v1` |
| `UI_API_DOCS_URL` / `NEXT_PUBLIC_API_DOCS_URL` | `https://<HOST>/prowler/api/v1/docs` |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1,api,prowler-api,<HOST>` |
| `DJANGO_CORS_ALLOWED_ORIGINS` | `https://<HOST>,http://127.0.0.1:8090` |
| `AUTH_SECRET` | `openssl rand -hex 32` |
| `VRIKA_BRIDGE_SECRET` | `openssl rand -hex 32` |
| `POSTGRES_ADMIN_PASSWORD` | strong password |
| `POSTGRES_PASSWORD` | strong password |
| `NEO4J_PASSWORD` | strong password |
| `VRIKA_LLM_API_KEY` | OpenRouter key (optional, for Lighthouse AI) |

Keep as-is:
- `PROWLER_API_VERSION=local`
- `API_BASE_URL=http://prowler-api:8080/api/v1`
- `VRIKA_PDF_BRANDING=true`
- `NEXT_PUBLIC_BASE_PATH=/prowler`, `NEXT_PUBLIC_VRIKA_EMBED_MODE=true`

> `.env` is committed in the repo as a POC default — always overwrite it with
> real per-host secrets; never reuse the demo secrets in production.

## 4. Build local images

```bash
# API image (used by api, worker, worker-beat)
docker build -t prowlercloud/prowler-api:local -f api/Dockerfile api/

# UI image + starts ui/nginx (script does a --no-cache build with typecheck)
bash rebuild-prowler-ui.sh
```

## 5. Start the full stack

```bash
docker compose -f docker-compose.yml -f docker-compose.vrika.yml up -d
```

`api-init` runs Django migrations automatically (including
`0098_tenant_branding`), then the remaining services start. First cold start is
slow (~3 min until `api` is healthy: migrations + compliance cache warm-up).

## 6. Verify

```bash
docker compose -f docker-compose.yml -f docker-compose.vrika.yml ps
curl -sf http://127.0.0.1:8090/prowler/api/health && echo OK
```

Open `https://<HOST>/prowler/sign-in` (or `http://<HOST>:8090/prowler/sign-in`
without host TLS) and create the first account.

---

## Notes / gotchas

- **TLS**: the stack nginx serves plain HTTP on 8090. For HTTPS put a host-level
  nginx (with certs) in front, proxying 443 -> 127.0.0.1:8090. The stack nginx
  container caches upstream IPs at startup; if you recreate `ui`/`api`, reload it
  with `docker exec vrika-prowler-nginx nginx -s reload` (only needed for an
  external/orphan nginx; the compose-managed one restarts with the stack).
- **Redeploys** after code changes:
  1. `git pull`
  2. `docker build -t prowlercloud/prowler-api:local -f api/Dockerfile api/`
  3. `docker compose -f docker-compose.yml -f docker-compose.vrika.yml up -d api worker --force-recreate`
  4. `bash rebuild-prowler-ui.sh` (only if UI changed)
- **Data**: Postgres/Neo4j/Valkey persist in named Docker volumes. A fresh deploy
  starts empty. To migrate data, `pg_dump`/restore Postgres and back up Neo4j
  databases separately.
- **Port conflicts**: on a shared host, watch for 6379 (valkey) / 5432 (postgres)
  clashes with other stacks — the overlay resets published ports so services are
  internal-only, but a host-level service on 8090 will block nginx.
