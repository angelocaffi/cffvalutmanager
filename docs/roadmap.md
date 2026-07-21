# Roadmap

## Fase 0 — Fondamenta (prerequisito a tutto il resto)

- [x] Decisione definitiva: Blazor WebAssembly hosted, SQL Server ([architecture.md](architecture.md))
- [x] Scaffolding solution: progetti `Web.Client`, `Web`, `Api`, `Domain`, `Application`, `Infrastructure`, `Crypto` + test projects, build verificata
- [x] Entità Domain: Tenant, User, Vault, VaultItem, Folder, Tag, VaultItemTag, AuditLogEntry, OneTimeCode, con enum ed invarianti (es. `User.CreateSuperAdmin`/`CreateTenantUser`)
- [x] Implementazione `CffVaultManager.Crypto`: derivazione chiave (Argon2id, DegreeOfParallelism forzato a 1 per compatibilità WASM), DEK/KEK, cifratura AES-256-GCM (`AesGcmCipherService` su `BouncyCastle.Cryptography`, non sul BCL — `System.Security.Cryptography.AesGcm` non funziona sotto Blazor WASM, verificato live in browser) ([features/encryption-key-management.md](features/encryption-key-management.md))
- [x] Modello multi-tenant: `CffVaultManagerDbContext` EF Core, `ITenantContext`, global query filter per `TenantId` su tutte le entità tenant-scoped, `ITenantAdministrationService` come unico bypass amministrativo (solo metadati, mai `EncryptedPayload`/`EncryptedDek`) ([multi-tenancy.md](multi-tenancy.md))
- [x] Modello dati + migration EF Core (`InitialCreate`) su SQL Server ([data-model.md](data-model.md))
- [x] Test di isolamento tenant (IDOR): 7 casi su provider SQLite in-memory (isolamento Vault/VaultItem/User/AuditLog, fail-closed su contesto non risolto, bypass amministrativo controllato)
- [x] Ruoli e autorizzazione applicativa: handler `Bearer` custom su `IJwtTokenService`, middleware di risoluzione tenant (`tenant_id` claim → `ITenantContext`), policy-based authorization ASP.NET Core (`[Authorize(Roles = ...)]`) combinata col tenant filter ([features/roles-permissions.md](features/roles-permissions.md)) — coperto da `CffVaultManager.Api.Tests` end-to-end via HTTP

## Fase 1 — MVP

- [x] Provisioning tenant: creazione organizzazione + primo Admin, esposto su `POST /api/tenants` ([multi-tenancy.md](multi-tenancy.md#provisioning-di-un-nuovo-tenant))
- [~] Autenticazione: login (con risoluzione tenant), MFA TOTP esposti su `/api/auth/*` ([features/authentication.md](features/authentication.md)) — l'MVP resta con **solo TOTP** come baseline MFA; l'Email OTP è rimandato alla Fase 3. Manca ancora: verifica email in registrazione, cambio master password, logout remoto/invalidazione sessioni, rate limiting sui tentativi (previsto in Fase 2)
- [x] Vault core: vault personali, cartelle, tag, filtri/ordinamento, cestino con soft-delete ed eliminazione fisica esplicita ([features/vault-core.md](features/vault-core.md)) — ricerca full-text resta client-side dopo decifratura, come da design; vault di organizzazione non ancora implementati (proprietà `OwnerUserId` è l'unico controllo di accesso sui vault personali)
- [~] Gestione password: CRUD + generatore ([features/password-manager.md](features/password-manager.md)) — CRUD lato server già coperto genericamente da `VaultItem`/`Type=Password` (vault-core); generatore password/passphrase client-side implementato in `CffVaultManager.Crypto.PasswordGeneratorService` (RNG crittografico, no `Random`, 56 test). Manca ancora: le pagine Blazor (`Web.Client`) per creare/vedere/modificare le voci password, cifratura/decifratura lato client del payload, indicatore di forza, cronologia password nel payload cifrato
- [~] Gestione carte di credito: CRUD + mascheramento ([features/credit-cards.md](features/credit-cards.md)) — CRUD lato server già coperto genericamente da `VaultItem`/`Type=CreditCard` (vault-core); validazione Luhn, riconoscimento circuito da prefisso e mascheramento numero implementati client-side in `CffVaultManager.Crypto.CardValidationService` (29 test). Manca ancora: le pagine Blazor (`Web.Client`) per creare/vedere/modificare le voci carta, cifratura/decifratura lato client del payload, conferma esplicita per il reveal di numero/CVV, alert di scadenza (rimandato — collegato a notifications.md, v2)
- [~] Gestione crypto wallet: CRUD + validazione indirizzi/seed phrase ([features/crypto-wallets.md](features/crypto-wallets.md)) — CRUD lato server già coperto genericamente da `VaultItem`/`Type=CryptoWallet` (vault-core, nuovo valore enum, nessuna migrazione necessaria); riconoscimento rete da prefisso, validazione di plausibilità indirizzo/seed phrase e mascheramento implementati client-side in `CffVaultManager.Crypto.CryptoWalletValidationService` (37 test). Deliberatamente **non** implementata la validazione crittografica completa (checksum Base58Check/EIP-55, wordlist/checksum BIP-39 — richiede la wordlist canonica a 2048 parole, non riproducibile in modo affidabile senza una fonte verificata). Manca ancora: le pagine Blazor (`Web.Client`), cifratura/decifratura lato client del payload, conferma esplicita per il reveal di chiave privata/seed phrase
- [ ] Secrets generici: note sicure, campi custom ([features/vault-core.md](features/vault-core.md#secrets-generici))
- [~] Vault di organizzazione (scope minimo): crittografia asimmetrica, inviti nello stesso tenant ([features/sharing-access-control.md](features/sharing-access-control.md)) — schema X25519 (ECDH) + HKDF-SHA256 + AES-256-GCM via `BouncyCastle.Cryptography` (`X25519KeyExchangeService`), verificato live in Blazor WASM prima dell'implementazione; nuova entità `VaultMembership` (permesso Read/ReadWrite, DEK del vault cifrata per-membro, mai in chiaro lato server); `VaultAccessGuard.GetAccessibleVaultAsync` sostituisce il controllo solo-proprietario per `VaultItemService`/`FolderService`/`TagService`, con gate di permesso sulle scritture (`InsufficientVaultPermissionException` → 403); endpoint `POST/GET /api/vaults/organization`, `POST /api/vaults/{vaultId}/memberships`, `POST .../memberships/{userId}/revoke`, `GET .../memberships`, `GET /api/tenant/users/{userId}/public-key`. La revoca ruota la DEK del vault e ri-cifra tutti gli item correnti (non un semplice blocco futuro delle API), con validazione server-side che l'insieme di item ri-cifrati e di membri ri-condivisi corrisponda esattamente allo stato corrente. 62 nuovi test (12 Crypto + 32 Infrastructure + 18 Api; 258 in totale nella solution). Manca ancora: le pagine Blazor (`Web.Client`), ruoli fini oltre Read/ReadWrite (rimandato a Fase 4), condivisione di singole voci (backlog v2)
- [~] Audit log di base, incluso tracciamento eventi di tenant/ruolo ([features/audit-log.md](features/audit-log.md)) — scrittura eventi cablata in `VaultItemService` (Created/Viewed/Updated/Deleted) e `MfaSetupService` (MfaEnabled); nuovo evento `Revealed` registrato tramite `POST /api/vaults/{vaultId}/items/{itemId}/reveal` (il server non può osservare il reveal da solo, va richiamato esplicitamente dal client). Lettura via `GET /api/audit` con filtri per azione/intervallo temporale e paginazione: Admin vede tutto il tenant, Operator solo le proprie azioni (`IAuditLogService`, 11 test Infrastructure + 4 test Api). Manca ancora: vista utente "Attività recenti", retention/rotazione configurabile (default 90gg), notifiche email per eventi critici (v2, collegato a notifications.md)
- [ ] Dashboard SuperAdmin minima: lista tenant, sospensione, metadati (nessun accesso a secrets)

## Fase 2 — Hardening e qualità

- [ ] Rate limiting e lockout su login
- [ ] Logout remoto / gestione sessioni attive
- [ ] Review di sicurezza completa contro la checklist in [security-model.md](security-model.md)
- [ ] Test di integrazione end-to-end su flussi critici (login, cifratura/decifratura, cambio master password)

## Fase 3 — Feature avanzate (post-MVP)

- [ ] Password health / dashboard sicurezza ([features/password-health.md](features/password-health.md))
- [ ] Import / export ([features/import-export.md](features/import-export.md))
- [ ] Notifiche (scadenza carte, alert sicurezza) ([features/notifications.md](features/notifications.md))
- [ ] WebAuthn/Passkey come alternativa a TOTP
- [ ] Email OTP come fattore MFA aggiuntivo/alternativo al TOTP (inclusa verifica email in registrazione) ([features/authentication.md](features/authentication.md))

## Fase 4 — Estensioni condivisione

- [ ] Condivisione granulare di singole voci tra utenti dello stesso tenant, ruoli fini (owner/editor/viewer) ([features/sharing-access-control.md](features/sharing-access-control.md))

## Note

Ogni fase successiva alla 0 presuppone che la crittografia core **e** il modello multi-tenant siano implementati, testati e revisionati: nessuna feature che tocca secrets va sviluppata prima che `CffVaultManager.Crypto` sia stabile e prima che l'isolamento per `TenantId` sia verificato da test dedicati.
