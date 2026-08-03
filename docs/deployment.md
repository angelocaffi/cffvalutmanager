# Deployment (Docker)

Container setup for a self-hosted deployment: `CffVaultManager.Api` and `CffVaultManager.Web`
(the Blazor WASM host) as two separate images, plus SQL Server, wired together by
`docker-compose.yml` at the repo root.

## Prerequisites

1. Copy `.env.example` to `.env` and fill in every required value (see comments in the file).
   `.env` is gitignored — never commit real secrets.
2. Point the Web.Client at your public Api URL: edit
   `src/CffVaultManager.Web.Client/wwwroot/appsettings.Production.json` and replace
   `Api.BaseUrl` with the URL the *browser* will actually reach the Api on (a Docker-internal
   service name like `http://api:8080` will not work — this file is fetched by the browser at
   runtime, not resolved server-side). If you'd rather not rebuild the `web` image per
   environment, bind-mount your own file over it instead, e.g. in `docker-compose.yml`:
   ```yaml
   web:
     volumes:
       - ./deploy/appsettings.Production.json:/app/wwwroot/appsettings.Production.json:ro
   ```

## Build and run

```
docker compose up --build -d
```

- Api: `http://localhost:8080` (container listens on plain HTTP only — see "TLS" below)
- Web: `http://localhost:8081`

## Apply database migrations

This project never auto-migrates on startup (see CLAUDE.md). `sqlserver`'s port `1433` is
published to the host as `15433` by `docker-compose.yml` (not `1433` — a machine with its own
local SQL Server instance already owns that port, and Docker Desktop's forwarding silently loses
the race to it, so `localhost:1433` can end up hitting the wrong server). Apply migrations from
your machine against `15433`:

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

Both containers deliberately expose plain HTTP only (`ASPNETCORE_URLS=http://+:8080`). TLS
termination is left to whatever reverse proxy you put in front (Caddy, nginx, Traefik, a cloud
load balancer, ...) — not part of this compose file, since the right choice depends on your
hosting target and certificate strategy. Once you have one, point it at ports `8080`/`8081` and
set `ReverseProxy:KnownProxies` (Api) to the proxy's address so `ForwardedHeaders` are honored for
rate-limiting/audit IP attribution (see `Program.cs`).

## Notes

- SQL Server data persists in the `sqlserver-data` named volume; back it up like any production
  database.
- `PayPal:ClientId`/`ClientSecret` and `Email:SmtpHost` are optional — leaving them unset disables
  billing/checkout (503) and falls back to `LoggingEmailSender` respectively, same as local dev.
