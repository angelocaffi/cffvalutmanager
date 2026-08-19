# CffVaultManager

Gestionale web per password, carte di credito e secrets in generale — un password manager self-hosted con crittografia end-to-end applicativa.

## Stack tecnico

- **Backend**: ASP.NET Core Web API (.NET 10 LTS)
- **Frontend**: Blazor WebAssembly (hosted) — confermato, vedi [docs/architecture.md](docs/architecture.md)
- **Storage**: PostgreSQL, multi-tenant a schema condiviso con isolamento per `TenantId` — vedi [docs/multi-tenancy.md](docs/multi-tenancy.md)
- **Crittografia**: derivazione chiave da master password (Argon2id/PBKDF2) + cifratura simmetrica (AES-256-GCM) — vedi [docs/security-model.md](docs/security-model.md)

> Stato: progetto in fase di scaffolding iniziale.

## Struttura documentazione

- [docs/architecture.md](docs/architecture.md) — architettura applicativa, layering, decisioni tecniche
- [docs/multi-tenancy.md](docs/multi-tenancy.md) — isolamento tenant, ruoli, scalabilità
- [docs/security-model.md](docs/security-model.md) — modello di minaccia, crittografia, gestione chiavi
- [docs/data-model.md](docs/data-model.md) — entità principali e relazioni
- [docs/roadmap.md](docs/roadmap.md) — fasi di sviluppo e priorità
- [docs/features/README.md](docs/features/README.md) — indice di tutte le feature

## Principi guida

1. **Zero-knowledge dove possibile**: il server non deve mai avere accesso in chiaro ai secrets. La master password (o la chiave da essa derivata) non lascia mai il client se non per operazioni di derivazione controllate. Questo vale anche per i **superadmin**: nessun ruolo, nemmeno il più privilegiato, può decifrare i secrets di un tenant.
2. **Isolamento multi-tenant per difetto**: ogni query, ogni riga, ogni voce del vault appartiene a un tenant. L'accesso cross-tenant è impossibile per operatori/admin ed è limitato ai soli superadmin per operazioni amministrative sulla piattaforma (mai sui dati cifrati) — vedi [docs/multi-tenancy.md](docs/multi-tenancy.md).
3. **Difesa in profondità**: cifratura a riposo, cifratura in transito (TLS), autenticazione forte (MFA), audit logging.
4. **Nessuna feature ridondante**: ogni funzionalità deve avere uno scopo chiaro legato a gestione credenziali/secrets — evitare feature creep.
5. **Sicurezza prima di tutto**: qualunque scelta implementativa che riguarda crittografia, autenticazione, tenancy o storage di secrets va motivata esplicitamente in [docs/security-model.md](docs/security-model.md) o [docs/multi-tenancy.md](docs/multi-tenancy.md) prima di essere codificata.

## Struttura solution

```
src/
  CffVaultManager.Web           -> host ASP.NET Core del client Blazor WASM
  CffVaultManager.Web.Client    -> Blazor WebAssembly (UI, crittografia lato client)
  CffVaultManager.Api           -> ASP.NET Core minimal API
  CffVaultManager.Application   -> use case, DTO, validazione, risoluzione tenant
  CffVaultManager.Domain        -> entità di dominio, interfacce
  CffVaultManager.Infrastructure -> EF Core (PostgreSQL), repository tenant-aware
  CffVaultManager.Crypto        -> derivazione chiavi e cifratura, compatibile WASM
tests/
  CffVaultManager.Crypto.Tests
  CffVaultManager.Application.Tests
  CffVaultManager.Infrastructure.Tests -> business logic + isolamento tenant contro SQLite in-memory
  CffVaultManager.Api.Tests            -> autenticazione/autorizzazione end-to-end via WebApplicationFactory
```

Riferimenti tra progetti: `Application → Domain`, `Infrastructure → Domain, Application`, `Api → Application, Infrastructure, Domain`, `Web.Client → Crypto`, `Web → Web.Client`.

## Convenzioni di lavoro

- I nomi dei progetti .NET seguono il pattern `CffVaultManager.<Layer>`.
- Le migration del database vanno sempre accompagnate da uno script di rollback testato.
- Nessun secret, chiave o connection string reale va mai committato — usare user-secrets/variabili d'ambiente in sviluppo.
- `dotnet build CffVaultManager.slnx` / `dotnet test CffVaultManager.slnx` operano sull'intera solution.
