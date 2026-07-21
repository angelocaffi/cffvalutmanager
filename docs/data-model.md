# Modello dati

Entità principali (nomi indicativi, da raffinare in fase di implementazione). Tutti i campi marcati **[cifrato]** sono persistiti come ciphertext (AES-256-GCM) e mai in chiaro nel database — vedi [security-model.md](security-model.md). Tutte le entità marcate **[tenant-scoped]** hanno una colonna `TenantId` obbligatoria e sono soggette a global query filter EF Core — vedi [multi-tenancy.md](multi-tenancy.md).

## Tenant

| Campo | Note |
|---|---|
| Id | GUID |
| Name | nome organizzazione |
| Slug | identificativo univoco, usato per risoluzione tenant al login |
| Status | enum: `Active`, `Suspended`, `PendingSetup` |
| Plan / Limits | piano, limiti utenti/storage (se previsto un modello a pacchetti) |
| CreatedAt | |

## User **[tenant-scoped, tranne SuperAdmin]**

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant — **nullable solo per Role = SuperAdmin** |
| Email | univoco a livello di piattaforma, usato per login e risoluzione tenant |
| Role | enum: `SuperAdmin`, `Admin`, `Operator` — vedi [features/roles-permissions.md](features/roles-permissions.md) |
| MasterPasswordHash | hash Argon2id della master password (solo se verifica lato server) |
| MasterPasswordSalt | salt univoco |
| EncryptedDek | DEK cifrata con la KEK derivata dalla master password |
| MfaEnabled / MfaSecret | secret TOTP **[cifrato]** |
| MfaEmailOtpEnabled | bool — abilita l'Email OTP come fattore MFA aggiuntivo/alternativo al TOTP (vedi [features/authentication.md](features/authentication.md)) |
| PublicKey | nullable — chiave pubblica X25519 (32 byte), in chiaro per definizione; usata per condividere DEK di vault di organizzazione (vedi [features/sharing-access-control.md](features/sharing-access-control.md)) |
| EncryptedPrivateKey | nullable **[cifrato]** — chiave privata X25519 cifrata con la propria DEK (non una KEK separata), come qualunque altro secret dell'utente |
| CreatedAt / LastLoginAt | |

> Nota: `SuperAdmin` non ha `TenantId` perché non appartiene a un'organizzazione — ha comunque una propria master password e una propria DEK per il proprio vault personale (se previsto), ma nessun accesso ai vault dei tenant.

## OneTimeCode **[tenant-scoped indirettamente tramite UserId]**

Codice one-time monouso usato per verifica email in registrazione, Email OTP come fattore MFA e (backlog v2) recovery. Vedi [features/authentication.md](features/authentication.md).

| Campo | Note |
|---|---|
| Id | GUID |
| UserId | FK a User — il tenant è derivato dall'utente, non memorizzato direttamente |
| Purpose | enum: `EmailVerification`, `MfaLogin`, `AccountRecovery` |
| CodeHash | hash del codice one-time — **mai il codice in chiaro**, mai loggato (vedi Note di implementazione) |
| ExpiresAt | scadenza breve (5-10 min) oltre la quale il codice non è più valido |
| ConsumedAt | nullable — valorizzato al primo utilizzo con successo (garantisce il monouso) |
| AttemptCount | numero di tentativi di verifica effettuati |
| MaxAttempts | soglia oltre la quale il codice è invalidato e scatta il lockout (es. 5) |
| CreatedAt | usato anche per il cooldown di reinvio (es. 60s) |
| IpAddress / UserAgent | metadato contestuale della richiesta |

## Vault **[tenant-scoped]**

Contenitore logico di secrets: vault personale di un utente o vault condiviso di organizzazione (vedi [features/sharing-access-control.md](features/sharing-access-control.md)).

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant (ridondante rispetto a OwnerUserId.TenantId, ma denormalizzato per poter filtrare/indicizzare senza join) |
| OwnerUserId | FK a User, nullable se `IsOrganizationVault = true` |
| IsOrganizationVault | bool — se true, l'accesso è governato da inviti espliciti cifrati asimmetricamente, non da ownership singola |
| Name | nome del vault (es. "Personale", "IT Team") |

## VaultMembership **[tenant-scoped]**

Accesso di un utente a un vault di organizzazione (mai a un vault personale, che resta ownership-only). La DEK del vault non esiste mai come colonna cifrata unica sul `Vault`: esiste solo come N copie indipendenti, una per membro attivo, qui. Vedi [features/sharing-access-control.md](features/sharing-access-control.md) per lo schema crittografico completo (X25519 + HKDF-SHA256 + AES-256-GCM).

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant (denormalizzato) |
| VaultId | FK a Vault — deve avere `IsOrganizationVault = true` |
| UserId | FK a User — deve appartenere allo stesso Tenant del Vault |
| Permission | enum: `Read`, `ReadWrite` |
| WrappedVaultDek | **[cifrato]** — DEK del vault cifrata per questo membro (AES-256-GCM con chiave derivata via ECDH+HKDF dalla sua chiave pubblica) |
| EphemeralPublicKey | chiave pubblica X25519 effimera del mittente usata per questo specifico wrapping — non riutilizzata tra membership |
| InvitedByUserId | FK a User — chi ha eseguito l'invito |
| CreatedAt | |
| RevokedAt | nullable — la riga resta per audit anche dopo la revoca; solo `RevokedAt IS NULL` conta come accesso attivo |

> Nota: indice univoco filtrato `(TenantId, VaultId, UserId) WHERE RevokedAt IS NULL` — al più una membership attiva per utente per vault, ma una nuova membership dopo una revoca è ammessa (nuova riga).

## VaultItem (entità base per password / carte / secrets generici) **[tenant-scoped]**

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant (denormalizzato, vedi sopra) |
| VaultId | FK a Vault |
| Type | enum: `Password`, `CreditCard`, `SecureNote`, `GenericSecret`, `CryptoWallet` |
| EncryptedPayload | **[cifrato]** — JSON serializzato specifico per tipo, poi cifrato |
| FolderId / Tags | organizzazione (vedi [features/vault-core.md](features/vault-core.md)) |
| IsFavorite | |
| CreatedAt / UpdatedAt | |
| LastAccessedAt | per feature di "usati di recente" |

> Nota: non esiste una colonna `Nonce` dedicata. Il nonce AES-GCM è già incapsulato nel formato `EncryptedBlob` all'interno di `EncryptedPayload` (vedi `CffVaultManager.Crypto.EncryptedBlob`: `[version][nonce][ciphertext][tag]`), quindi una colonna separata sarebbe ridondante.

### Payload — Password (dentro EncryptedPayload)

- Title, Username, Password **[cifrato]**, URL, Notes **[cifrato]**, PasswordHistory[] **[cifrato]**

### Payload — CreditCard (dentro EncryptedPayload)

- CardholderName, CardNumber **[cifrato]**, ExpiryMonth/Year, CVV **[cifrato]**, Brand (Visa/Mastercard/...), Notes **[cifrato]**

### Payload — SecureNote / GenericSecret (dentro EncryptedPayload)

- Title, Content **[cifrato]**, campi custom key-value **[cifrato]** (per secrets generici tipo API key, chiavi SSH, ecc.)

### Payload — CryptoWallet (dentro EncryptedPayload)

- Label, Network (Bitcoin/Ethereum/Litecoin/altro), WalletAddress[] (uno o più indirizzi pubblici), PrivateKey **[cifrato]**, Mnemonic/SeedPhrase **[cifrato]**, Notes **[cifrato]** — vedi [features/crypto-wallets.md](features/crypto-wallets.md)

## Folder / Tag **[tenant-scoped]**

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant |
| VaultId | FK |
| Name | in chiaro (metadato di organizzazione, non sensibile) |

## AuditLogEntry **[tenant-scoped, tranne eventi di piattaforma SuperAdmin]**

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant — nullable per eventi di piattaforma generati da un SuperAdmin |
| UserId | chi ha eseguito l'azione |
| VaultItemId | nullable, quale item (solo riferimento, mai contenuto) |
| Action | enum: `Created`, `Viewed`, `Updated`, `Deleted`, `Shared`, `Revoked`, `Revealed`, `MfaEnabled`, `LoginSuccess`, `LoginFailed`, `MfaChallenge`, `EmailOtpRequested`, `EmailOtpVerified`, `EmailOtpFailed`, `TenantProvisioned`, `TenantSuspended`, `TenantReactivated`, `UserRoleChanged` |
| Timestamp | |
| IpAddress / UserAgent | metadato contestuale |

## Relazioni

```
Tenant 1---N User (tranne SuperAdmin, TenantId nullo)
Tenant 1---N Vault 1---N VaultItem N---1 Folder
User 1---N AuditLogEntry
User 1---N OneTimeCode
VaultItem N---N Tag
Vault 1---N VaultMembership N---1 User (solo vault di organizzazione)
```

## Note di implementazione

- Nessuna colonna DB deve contenere secrets in chiaro, nemmeno temporaneamente (attenzione a EF Core change tracking / logging delle query in ambienti non-prod).
- Il codice OTP (`OneTimeCode`) non va **mai** persistito in chiaro: si salva solo `CodeHash`, e il codice generato non deve comparire in log, tracce o audit — nemmeno il payload dell'email inviata va conservato oltre l'invio.
- Ogni tabella `[tenant-scoped]` ha un global query filter EF Core su `TenantId` (vedi [multi-tenancy.md](multi-tenancy.md)) e indici composti con `TenantId` come prima colonna, es. `(TenantId, VaultId)`, `(TenantId, FolderId, Type)`.
- La ricerca full-text su contenuti cifrati non è possibile lato server: la ricerca sui campi sensibili va fatta client-side dopo decifratura, oppure tramite indici cifrati dedicati (fuori scope v1).
- Le foreign key verso entità tenant-scoped vanno sempre validate anche per `TenantId` corrispondente (non basta che l'Id esista, deve appartenere allo stesso tenant) — previene IDOR tramite riferimenti incrociati.
