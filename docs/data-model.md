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
| TrialEndsAt | `CreatedAt` + 30 giorni, impostato al provisioning — vedi [features/billing.md](features/billing.md) |
| PlanExpiresAt | nullable, esteso di 365 giorni ad ogni pagamento catturato — vedi [features/billing.md](features/billing.md) |
| CreatedAt | |

## PaymentTransaction **[tenant-scoped]**

Un tentativo di pagamento PayPal (singolo, non ricorrente) — vedi [features/billing.md](features/billing.md).

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant |
| CreatedByUserId | FK a User, sempre un `Admin` |
| PayPalOrderId | indice univoco, usato per idempotenza della cattura |
| Amount / Currency | decisi lato server alla creazione ordine, mai dal client |
| Status | enum: `Created`, `Captured`, `Failed` |
| CreatedAt / CapturedAt | `CapturedAt` nullable |
| PlanExpiresAtAfterCapture | copia storica di `Tenant.PlanExpiresAt` al momento della cattura |

## TenantBillingProfile **[tenant-scoped, 1:1 con Tenant]**

Dati anagrafici/fiscali dell'organizzazione, raccolti in fase di provisioning (vedi [multi-tenancy.md](multi-tenancy.md#provisioning-di-un-nuovo-tenant)) e riutilizzabili in futuro per selezione piano, addebito e generazione fattura, senza richiederli una seconda volta.

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant, univoco (una sola riga per tenant) |
| LegalName | ragione sociale, o nome e cognome per un privato |
| IsBusiness | bool — determina quali tra `VatNumber`/`TaxCode` sono obbligatori lato validazione applicativa |
| VatNumber | Partita IVA, nullable |
| TaxCode | Codice Fiscale, nullable |
| AddressLine / City / PostalCode / Province / Country | indirizzo di fatturazione |
| SdiCode | Codice Destinatario (7 caratteri) per la fatturazione elettronica italiana, nullable |
| PecAddress | indirizzo PEC, alternativa a `SdiCode` per la fatturazione elettronica, nullable |
| Phone | opzionale |
| CreatedAt / UpdatedAt | |

> Nota: nessun campo qui è **[cifrato]** — sono dati anagrafici/fiscali in chiaro, stessa classe di fiducia di `Tenant.Name`/`PlanName`, mai confusi con i secrets del vault. Vedi [security-model.md](security-model.md#dati-di-fatturazione-provisioning-tenant).

## TenantProvisioningRequest **[staging, non tenant-scoped — il Tenant non esiste ancora]**

Richiesta di creazione organizzazione in attesa di verifica email (vedi [multi-tenancy.md](multi-tenancy.md#provisioning-di-un-nuovo-tenant)). Consumata (eliminata) alla conferma riuscita, quando i suoi dati vengono promossi a `Tenant`/`User`/`TenantBillingProfile` reali; altrimenti scade da sola.

| Campo | Note |
|---|---|
| Id | GUID |
| Email | amministratore proposto |
| TenantName / TenantSlug | proposti — l'univocità è verificata sia alla richiesta (proattivo) sia alla conferma (chiude la race, stesso pattern di `ProvisionTenantService` oggi) |
| *(campi anagrafici)* | stessi campi di `TenantBillingProfile` sopra, copiati lì solo alla conferma riuscita |
| AuthHash / EncryptedDek / MasterPasswordSalt / KdfMemoryKb / KdfIterations / KdfVersion | materiale crypto opaco, identico a quanto oggi viaggia in `ProvisionTenantRequest` — mai decifrato dal server |
| CodeHash | hash del codice di verifica — stesso schema di `OneTimeCode.CodeHash` |
| ExpiresAt | finestra più ampia di un OTP normale (es. 24h) |
| AttemptCount / MaxAttempts | stesso schema anti-bruteforce di `OneTimeCode` |
| CreatedAt | usato anche per il cooldown di reinvio |
| IpAddress / UserAgent | metadato contestuale della richiesta |

> Nota: righe scadute e mai confermate vanno ripulite periodicamente (stesso pattern di `AuditLogRetentionHostedService`) — non contengono secrets in chiaro ma non hanno motivo di persistere indefinitamente.

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
| FailedLoginAttempts | contatore tentativi falliti consecutivi (password o codice MFA errati), azzerato su successo o su lockout |
| LockedUntil | nullable — finché è nel futuro, il login è rifiutato a prescindere dalle credenziali (vedi [features/authentication.md](features/authentication.md) rate limiting) |
| PublicKey | nullable — chiave pubblica X25519 (32 byte), in chiaro per definizione; usata per condividere DEK di vault di organizzazione (vedi [features/sharing-access-control.md](features/sharing-access-control.md)) |
| EncryptedPrivateKey | nullable **[cifrato]** — chiave privata X25519 cifrata con la propria DEK (non una KEK separata), come qualunque altro secret dell'utente |
| RecoveryEncryptedDek | nullable **[cifrato]** — DEK cifrata con la Recovery Key (non con la KEK), null se l'utente non ha generato un kit di recupero. Vedi [security-model.md](security-model.md#recovery-kit) |
| RecoveryKeyHash | nullable — hash server-side del `RecoveryAuthHash` client-side (stesso ruolo di `MasterPasswordHash` per `AuthHash`), null se nessun kit attivo |
| RecoveryKitGeneratedAt | nullable — data di generazione dell'ultimo kit attivo, mostrata in `/security`; azzerata insieme agli altri due campi quando il kit viene consumato o invalidato da una rotazione DEK |
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

## WebAuthnCredential **[tenant-scoped indirettamente tramite UserId]**

Una credenziale WebAuthn/FIDO2 registrata (Windows Hello, Touch ID, chiave di sicurezza, ecc.) — un utente può averne più di una, una per dispositivo. Vedi [features/authentication.md](features/authentication.md).

| Campo | Note |
|---|---|
| Id | GUID |
| UserId | FK a User |
| CredentialId | ID credenziale assegnato dall'authenticator — non un segreto, ma univoco a livello globale (indice unique) |
| PublicKey | chiave pubblica COSE, in chiaro per definizione (come `User.PublicKey`) |
| SignCount | contatore anti-clonazione dell'authenticator, aggiornato a ogni asserzione riuscita |
| AaGuid | identifica il modello di authenticator, solo informativo |
| Nickname | etichetta scelta dall'utente (es. "YubiKey", "Windows Hello") |
| Transports | hint di trasporto (usb/nfc/ble/interno), solo informativo |
| CreatedAt / LastUsedAt | |

## WebAuthnCeremony **[tenant-scoped indirettamente tramite UserId]**

Stato lato server di una cerimonia WebAuthn (registrazione o asserzione) in corso, tra la chiamata "begin" e "complete" — le opzioni generate per il client vanno ripresentate identiche in fase di verifica, stesso pattern a riga-breve di `OneTimeCode`.

| Campo | Note |
|---|---|
| Id | GUID |
| UserId | FK a User |
| Purpose | enum: `Registration`, `Assertion` |
| OptionsJson | `CredentialCreateOptions`/`AssertionOptions` serializzati |
| ExpiresAt | scadenza breve (5 min) |
| ConsumedAt | nullable — valorizzato al completamento (successo o fallimento) |
| CreatedAt | |

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
| Permission | enum: `Read`, `ReadWrite`, `Owner` (`Owner` implica tutte le capacità di `ReadWrite` più l'autorità di invitare/revocare membri — vedi [features/sharing-access-control.md](features/sharing-access-control.md)) |
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

## ItemMembership **[tenant-scoped]**

Accesso di un utente a una singola voce condivisa (vedi [features/sharing-access-control.md](features/sharing-access-control.md#condivisione-live-di-singola-voce-fase-4-backend-implementato)), indipendente dal vault che la contiene. Mirror di `VaultMembership` a livello di voce invece che di vault: la chiave della voce non esiste mai come colonna cifrata unica, solo come N copie indipendenti (una per membro attivo, proprietario incluso) qui.

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant (denormalizzato) |
| VaultItemId | FK a VaultItem |
| UserId | FK a User |
| Permission | enum `ItemSharePermission`: `Viewer`, `Editor`, `Owner` (distinto da `VaultPermission`, che resta solo per i vault) |
| WrappedItemKey | **[cifrato]** — chiave della voce cifrata per questo membro (AES-256-GCM con chiave derivata via ECDH+HKDF) |
| EphemeralPublicKey | chiave pubblica X25519 effimera del mittente usata per questo specifico wrapping |
| InvitedByUserId | FK a User |
| CreatedAt | |
| RevokedAt | nullable — la riga resta per audit anche dopo la revoca |

> Nota: indice univoco filtrato `(TenantId, VaultItemId, UserId) WHERE RevokedAt IS NULL` — al più una membership attiva per utente per voce.

## ExternalShareLink **[tenant-scoped]**

Link di condivisione a scadenza verso una singola voce, per chi non ha un account (vedi [features/sharing-access-control.md](features/sharing-access-control.md#link-di-condivisione-esterna-fase-4-implementato)). `EncryptedPayload` è uno snapshot cifrato con una chiave monouso che non lascia mai il browser del proprietario — il server non la vede né la deriva.

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant (denormalizzato) — la lettura pubblica bypassa comunque il filtro tenant per token (vedi doc feature) |
| VaultItemId | FK a VaultItem |
| CreatedByUserId | FK a User |
| Token | stringa casuale ad alta entropia (256 bit), univoca — mai l'Id, è la chiave di lookup pubblica |
| EncryptedPayload | **[cifrato]** — snapshot minimale (Titolo/Username/Password/URL), cifrato con una chiave monouso mai persistita |
| ExpiresAt | configurabile dal client, clampata lato server (1 minuto — 7 giorni) |
| CreatedAt | |
| RevokedAt | nullable — una riga scaduta o revocata viene eliminata al primo tentativo di accesso, non conservata per audit come `VaultMembership` |

## AuditLogEntry **[tenant-scoped, tranne eventi di piattaforma SuperAdmin]**

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant — nullable per eventi di piattaforma generati da un SuperAdmin |
| UserId | chi ha eseguito l'azione |
| VaultItemId | nullable, quale item (solo riferimento, mai contenuto) |
| Action | enum: `Created`, `Viewed`, `Updated`, `Deleted`, `Shared`, `Revoked`, `Revealed`, `MfaEnabled`, `LoginSuccess`, `LoginFailed`, `AccountLocked`, `SessionsRevoked`, `MfaChallenge`, `EmailOtpRequested`, `EmailOtpVerified`, `EmailOtpFailed`, `TenantProvisioned`, `TenantSuspended`, `TenantReactivated`, `UserRoleChanged`, `PermanentlyDeleted`, `MasterPasswordChanged`, `MfaEmailOtpEnabled`, `MfaEmailOtpDisabled`, `WebAuthnCredentialRegistered`, `WebAuthnCredentialRemoved`, `ExternalShareLinkCreated`, `ExternalShareLinkRevoked`, `ItemMembershipGranted`, `ItemMembershipRevoked`, `DekRotated`, `RecoveryKitGenerated`, `AccountRecovered` |
| Timestamp | |
| IpAddress / UserAgent | metadato contestuale |

## Notification **[tenant-scoped]**

Il canale in-app degli alert di sicurezza (vedi [features/notifications.md](features/notifications.md)) — entità dedicata, non un riuso di `AuditLogEntry` (che mescola troppi tipi di evento e non ha stato letto/non letto).

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant |
| UserId | FK a User — destinatario |
| Type | enum: `NewLoginFromUnknownIp`, `MasterPasswordChanged`, `MfaFactorDisabled`, `AccountRecovered`, `RecoveryKitInvalidated` |
| Message | breve, mai un secret |
| CreatedAt | |
| ReadAt | nullable — impostato da `MarkAsRead()` |

Indice `(TenantId, UserId, ReadAt)` per il conteggio non-letti veloce.

## Relazioni

```
Tenant 1---1 TenantBillingProfile
TenantProvisioningRequest (indipendente — nessuna FK, promossa a Tenant/User/TenantBillingProfile alla conferma)
Tenant 1---N User (tranne SuperAdmin, TenantId nullo)
Tenant 1---N Vault 1---N VaultItem N---1 Folder
User 1---N AuditLogEntry
User 1---N Notification
User 1---N OneTimeCode
User 1---N WebAuthnCredential
User 1---N WebAuthnCeremony
VaultItem N---N Tag
Vault 1---N VaultMembership N---1 User (solo vault di organizzazione)
VaultItem 1---N ExternalShareLink
VaultItem 1---N ItemMembership N---1 User
```

## Note di implementazione

- Nessuna colonna DB deve contenere secrets in chiaro, nemmeno temporaneamente (attenzione a EF Core change tracking / logging delle query in ambienti non-prod).
- Il codice OTP (`OneTimeCode`) non va **mai** persistito in chiaro: si salva solo `CodeHash`, e il codice generato non deve comparire in log, tracce o audit — nemmeno il payload dell'email inviata va conservato oltre l'invio.
- Ogni tabella `[tenant-scoped]` ha un global query filter EF Core su `TenantId` (vedi [multi-tenancy.md](multi-tenancy.md)) e indici composti con `TenantId` come prima colonna, es. `(TenantId, VaultId)`, `(TenantId, FolderId, Type)`.
- La ricerca full-text su contenuti cifrati non è possibile lato server: la ricerca sui campi sensibili va fatta client-side dopo decifratura, oppure tramite indici cifrati dedicati (fuori scope v1).
- Le foreign key verso entità tenant-scoped vanno sempre validate anche per `TenantId` corrispondente (non basta che l'Id esista, deve appartenere allo stesso tenant) — previene IDOR tramite riferimenti incrociati.
- **`Vault → Folder` e `Vault → Tag` sono `OnDelete(Restrict)`, non `Cascade`** (a differenza di `Vault → VaultItem`, che resta `Cascade`): SQL Server rifiuta lo schema altrimenti, perché un delete su `Vault` raggiungerebbe `VaultItems`/`VaultItemTags` attraverso due percorsi di cascade in competizione (direttamente, e indirettamente via `Folder`/`Tag`) — "multiple cascade paths", un limite specifico di SQL Server che SQLite non applica. Il bug è rimasto invisibile fino a quando le migration sono state applicate per la prima volta contro una vera istanza SQL Server (tutta la suite di test gira su SQLite in-memory); nessuna feature di eliminazione vault esiste ancora, quindi non c'è comportamento applicativo da riscrivere — quando questa feature verrà implementata, la pulizia di cartelle/tag andrà gestita lì esplicitamente, come già avviene altrove in questo codebase per il cleanup con significato di business. Nota: il vincolo di SQL Server che ha originato questa scelta non esiste su PostgreSQL (vedi punto sotto sul cambio di motore) — lo schema resta comunque `Restrict` anche dopo la migrazione, perché nessun comportamento applicativo dipende dal cambiarlo ora; tornare a `Cascade` è una decisione a sé, da valutare quando (e se) verrà implementata la cancellazione vault.
- **Motore database: SQL Server → PostgreSQL.** La VM di produzione è stata spostata su un'istanza Oracle Cloud Ampere (ARM64) per restare nella fascia Always Free — l'immagine Docker ufficiale di SQL Server (`mcr.microsoft.com/mssql/server`) supporta solo host x86-64 (emulazione esplicitamente non testata/non supportata da Microsoft). L'alternativa ARM64-nativa della stessa famiglia, Azure SQL Edge, è stata scartata perché ritirata da Microsoft il 1° ottobre 2025 (nessuna patch di sicurezza da allora) — inaccettabile come motore dati per un password manager. PostgreSQL ha un'immagine ufficiale realmente multi-arch (ARM64+x86-64) e continua a ricevere aggiornamenti attivi.
- **Case-sensitivity di `Email` e `Slug`: normalizzati a lowercase, sempre.** SQL Server usa di default una collation case-insensitive (`SQL_Latin1_General_CP1_CI_AS`); PostgreSQL è case-sensitive di default. Senza normalizzazione, l'indice univoco su `User.Email`/`Tenant.Slug` smetterebbe silenziosamente di impedire duplicati case-variant (es. `Alice@x.com` e `alice@x.com` diventerebbero due account distinti) — oltre a essere confuso, è una superficie di phishing/account-confusion reale, non solo un dettaglio tecnico. Scelta: normalizzare a lowercase ad ogni scrittura (`IdentifierNormalization.NormalizeEmail`/`NormalizeSlug`, `CffVaultManager.Domain`) e difensivamente anche ad ogni confronto — indipendente dal provider DB, quindi non fragile a un futuro ulteriore cambio di motore. I dati di produzione già esistenti vengono normalizzati durante la migrazione una tantum verso Postgres; un controllo preventivo blocca l'import (invece di sceglierlo silenziosamente) se esistono già righe che collidono una volta abbassate a lowercase.
