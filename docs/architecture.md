# Architettura

## Panoramica

CffVaultManager è organizzato come applicazione .NET a layer, con un'API come confine di sicurezza e un frontend Blazor che consuma quell'API (o la richiama in-process, a seconda della modalità Blazor scelta).

```
CffVaultManager.Web.Client   -> Blazor WebAssembly (UI, esegue crittografia lato client)
CffVaultManager.Web          -> host ASP.NET Core del client WASM (static files + eventualmente API)
CffVaultManager.Api          -> ASP.NET Core Web API (endpoint REST/minimal API)
CffVaultManager.Application  -> use case, orchestrazione, DTO, validazione, risoluzione tenant
CffVaultManager.Domain       -> entità di dominio, regole di business, interfacce
CffVaultManager.Infrastructure -> EF Core (PostgreSQL), repository tenant-aware, provider di crittografia, integrazioni esterne
CffVaultManager.Crypto       -> libreria dedicata a derivazione chiavi e cifratura (isolata per audit più semplice, compatibile WASM)
```

## Decisione: Blazor WebAssembly (confermato)

**Blazor WebAssembly, hosted da ASP.NET Core**, per allinearsi al principio zero-knowledge: derivazione chiave e decifratura dei secrets avvengono nel browser, l'API resta un backend puro che non vede mai dati in chiaro. Nessuna connessione persistente (SignalR) richiesta, superficie lato server ridotta al solo REST.

Conseguenze implementative:

- `CffVaultManager.Web.Client` (progetto Blazor WASM) contiene tutta la logica di crittografia lato client, tramite riferimento a `CffVaultManager.Crypto` (che deve restare compatibile con il target WASM — attenzione alla disponibilità delle API `System.Security.Cryptography` sotto WASM, da validare in fase di scaffolding).
- `CffVaultManager.Web` (host ASP.NET Core) serve i file statici WASM; l'API può essere hostata nello stesso processo (modello "hosted" classico) o restare come progetto `CffVaultManager.Api` separato dietro lo stesso reverse proxy — decisione di deployment, non di sicurezza: in entrambi i casi il confine resta "il server vede solo ciphertext".

## UI e tema visivo

Bootstrap 5.3 come base per markup/componenti, vendorizzato in locale (`CffVaultManager.Web/wwwroot/lib/bootstrap`, scaricato una tantum) invece che da CDN — coerente con l'approccio self-hosted del progetto: nessuna richiesta di rete verso terzi a runtime, funziona anche offline/air-gapped.

Palette campionata direttamente da `CffVaultmanager.svg` (non scelta a caso), sovrascritta tramite le CSS custom property di Bootstrap in `site-theme.css`:

- `--brand-navy` (`#0e4a78`) — bordo scuro dello scudo + wordmark. Diventa `--bs-primary`: navbar, titoli, bottoni primari.
- `--brand-teal` (`#157a93`) — tono intermedio del gradiente dello scudo. Diventa `--bs-secondary`: link, badge, bottoni secondari.
- `--brand-cyan` (`#00d9ec`) — il colore della serratura nel logo. Diventa `--bs-info`, riservato **solo** al momento di "sblocco" (bottone di login/verifica MFA, focus ring sui campi) — un solo accento con un significato preciso, non un colore usato ovunque.
- `--brand-bg` (`#f4f7f8`) — sfondo pagina, stesso tono freddo dello sfondo del logo.

Font stack di sistema (`-apple-system, Segoe UI, Roboto, ...`), nessun webfont caricato da CDN — stessa motivazione self-hosted/offline della scelta su Bootstrap.

## Confini di sicurezza

- L'**API** non accetta mai una master password in chiaro per operazioni di routine: solo per il login iniziale (via TLS), da cui deriva un token di sessione — mai la chiave di cifratura dei dati.
- La **chiave di cifratura dei dati** (Data Encryption Key, DEK) è generata client-side, cifrata con la chiave derivata dalla master password (Key Encryption Key, KEK) e salvata cifrata sul server. Vedi [security-model.md](security-model.md).
- Ogni operazione di lettura/scrittura di un secret passa da: **UI → API (autenticazione/autorizzazione) → Infrastructure (persistenza blob cifrato) → UI (decifratura locale)**.

## Comunicazione

- REST su HTTPS con autenticazione a token (JWT a breve scadenza + refresh token). Il JWT include `tenant_id` e `role` come claim, verificati ad ogni richiesta.
- Nessun dato sensibile in querystring o log applicativi (vedi [security-model.md](security-model.md) per policy di logging).

## Multi-tenancy e scalabilità

Il progetto è multi-tenant sin dalla Fase 0: ogni operatore/admin appartiene a un tenant (organizzazione) e non può mai vedere dati di un altro tenant. I superadmin sono l'unica eccezione, con accesso amministrativo cross-tenant ma **mai** ai secrets cifrati. Il modello completo — strategia di isolamento dati, risoluzione del tenant per richiesta, ruoli e considerazioni di scalabilità orizzontale — è documentato in [multi-tenancy.md](multi-tenancy.md).

## Testing

- Unit test su `Domain` e `Crypto` (in particolare: round-trip di cifratura, derivazione chiave, gestione errori su master password errata).
- Integration test su `Api` con database in-memory/container effimero.
- Nessun test deve mai loggare o serializzare secrets reali, nemmeno in ambienti di test.
