# Deployment (Docker)

Container setup for a self-hosted deployment: `CffVaultManager.Api` and `CffVaultManager.Web`
(the Blazor WASM host), SQL Server, and Caddy (TLS termination) wired together by
`docker-compose.yml` at the repo root. Caddy path-routes a single public domain: `/api/*` goes to
the Api container, everything else to Web — one domain, one certificate, no CORS needed in
practice (Api and Web are same-origin from the browser's point of view).

## Prerequisites

1. Copy `.env.example` to `.env` and fill in every required value (see comments in the file).
   `.env` is gitignored — never commit real secrets.
2. Point the Web.Client at your public domain: edit
   `src/CffVaultManager.Web.Client/wwwroot/appsettings.Production.json` and replace `Api.BaseUrl`
   with `https://<your PUBLIC_DOMAIN>` (root domain, no `/api` suffix — the API client code
   already appends `/api/...` itself). This file is fetched by the *browser* at runtime, so a
   Docker-internal name like `http://api:8080` will not work. If you'd rather not rebuild the
   `web` image per environment, bind-mount your own file over it instead, e.g. in
   `docker-compose.yml`:
   ```yaml
   web:
     volumes:
       - ./deploy/appsettings.Production.json:/app/wwwroot/appsettings.Production.json:ro
   ```

## Build and run

```
docker compose up --build -d
```

- Web (via Caddy, real TLS): `https://<PUBLIC_DOMAIN>`
- Api directly: `http://localhost:8080` (local-testing convenience only — see "TLS" below)
- Web directly: `http://localhost:8081` (same caveat)

## Apply database migrations

This project never auto-migrates on startup (see CLAUDE.md). `sqlserver`'s port `1433` is
published to the host as `15433` by `docker-compose.yml` (not `1433` — a machine with its own
local SQL Server instance already owns that port, and Docker Desktop's forwarding silently loses
the race to it, so `localhost:1433` can end up hitting the wrong server). Apply migrations from
your machine (or from the deployment host itself) against `15433`:

```
dotnet ef database update \
  --project src/CffVaultManager.Infrastructure \
  --startup-project src/CffVaultManager.Infrastructure \
  --connection "Server=localhost,15433;Database=CffVaultManager;User Id=sa;Password=<MSSQL_SA_PASSWORD from .env>;TrustServerCertificate=True"
```

`--startup-project` points at `CffVaultManager.Infrastructure` itself (not `Api`): the Api project
doesn't reference `Microsoft.EntityFrameworkCore.Design` (it's a `PrivateAssets="all"` reference on
Infrastructure, deliberately not propagated), and `Infrastructure`'s
`CffVaultManagerDbContextFactory` already provides the design-time `DbContext` the tools need.

Re-run this after every deployment that includes new migrations.

## TLS / reverse proxy

`api`/`web` expose plain HTTP only (`ASPNETCORE_URLS=http://+:8080`); the `caddy` service
terminates TLS (automatic Let's Encrypt certificate for `PUBLIC_DOMAIN`) and path-routes to both,
per `Caddyfile` at the repo root. `api`'s `ReverseProxy__KnownProxies__0` is pinned to Caddy's
static compose-network IP (`172.28.0.10`) so `ForwardedHeaders` are honored — without this, every
request would appear to come from Caddy's own IP, breaking rate-limiting and audit-log IP
attribution (see `Program.cs`). On the deployment host's *external* firewall, only ports `80`/`443`
should be open — `8080`/`8081` are for local testing without a domain and must not be reachable
from the internet.

## Free deployment: Oracle Cloud Free Tier + DuckDNS

A fully free way to put this online, matching the "self-hosted" nature of the project (full
control, real SQL Server, no re-architecture to a different database):

1. **Oracle Cloud account** (you do this): sign up at Oracle Cloud — the Always Free tier needs
   card verification for anti-abuse but the resources below are never billed.
2. **Always Free Compute VM** (you do this, in the OCI console): create an instance using shape
   `VM.Standard.A1.Flex` (Ampere ARM — the Always Free allowance is 4 OCPU / 24GB RAM total,
   shareable across up to 4 such instances), Ubuntu 24.04 image, and attach a **Reserved Public
   IP** (also Always Free) instead of the default ephemeral one, so the address survives a reboot.
3. **Open the firewall** (you do this, in the VM's attached Security List / Network Security
   Group): allow inbound TCP `80` and `443` from `0.0.0.0/0` (`22` for SSH is normally open by
   default already). Ubuntu's own `ufw`, if enabled, needs the same two ports allowed.
4. **Free domain** (you do this): register a subdomain at [DuckDNS](https://www.duckdns.org) (or
   any other free dynamic-DNS provider) pointing at the VM's reserved public IP — this becomes
   your `PUBLIC_DOMAIN` (e.g. `cffvault.duckdns.org`). Let's Encrypt (used by Caddy) needs a real
   resolvable domain; a bare IP address cannot get a certificate.
5. **On the VM** (SSH in, then): install Docker Engine + the Compose plugin (Docker's official
   `get-docker.sh` convenience script, or your distro's packages), clone this repository (or copy
   `docker-compose.yml`, `Caddyfile`, `.env`, and `src/` over), fill in `.env` with
   `PUBLIC_DOMAIN`/`CADDY_ACME_EMAIL`/a strong `JWT_SIGNING_KEY`/`MSSQL_SA_PASSWORD`, edit
   `wwwroot/appsettings.Production.json` as above, then:
   ```
   docker compose up --build -d
   ```
   followed by the migration step above (run from the VM itself against `localhost,15433`).

At that point `https://<PUBLIC_DOMAIN>` serves the app with a real Let's Encrypt certificate,
auto-renewed by Caddy. `PayPal`/`SMTP` remain optional — leave them unset in `.env` to disable
billing/checkout and fall back to `LoggingEmailSender`, respectively.

## Notes

- SQL Server data persists in the `sqlserver-data` named volume; back it up like any production
  database.
- Caddy's own state (ACME account key + issued certificates) persists in the `caddy-data` named
  volume — losing it just means re-issuing a certificate on next start, not an outage.
- `PayPal:ClientId`/`ClientSecret` and `Email:SmtpHost` are optional — leaving them unset disables
  billing/checkout (503) and falls back to `LoggingEmailSender` respectively, same as local dev.
