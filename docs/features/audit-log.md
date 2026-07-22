# Audit log

## Scopo

Tracciare le azioni compiute sul vault per rilevare accessi anomali e fornire trasparenza all'utente, senza mai esporre il contenuto dei secrets.

## Requisiti funzionali

- Registrazione di: login riusciti/falliti, sblocco/blocco vault, creazione/modifica/eliminazione voci, reveal di campi sensibili (numero carta, CVV, password), cambio master password, attivazione/disattivazione MFA, logout remoto.
- Vista utente: cronologia attività recenti (es. "Password 'GitHub' modificata il 12/07 alle 14:32").
- Filtri per tipo di azione e intervallo temporale.
- Conservazione configurabile (es. 90 giorni di default, poi rotazione/archiviazione).

## Requisiti di sicurezza

- **Mai** loggare il contenuto di un secret (password, numero carta, CVV, note), solo riferimenti a `VaultItemId`/`Title` non sensibile.
- Log immutabile per l'utente finale (nessuna modifica/cancellazione manuale delle voci di audit, salvo retention policy automatica).
- Metadati contestuali (IP, user agent) trattati secondo policy privacy — valutare GDPR se utenti UE (finalità: sicurezza, non profilazione).

## UX essenziale

- Sezione dedicata "Attività recenti" nel profilo/vault.
- Notifica opzionale via email per eventi critici (nuovo login da dispositivo sconosciuto, cambio master password) — collegata a [notifications.md](notifications.md).

## Stato

- Scrittura eventi: `AuditLogEntry` (già esistente da Fase 0) viene ora popolata anche per le azioni sul vault — `VaultItemService` scrive `Created`/`Viewed`/`Updated`/`Deleted` (soft-delete), oltre a `Updated` per `RestoreAsync`/`AssignTagAsync`/`RemoveTagAsync` e al nuovo `PermanentlyDeleted` per l'eliminazione fisica (distinto da `Deleted`, che resta il soft-delete verso il cestino); `FolderService`/`TagService` scrivono `Created`/`Updated`/`Deleted` sulle proprie mutazioni (nessun riferimento a `VaultItemId`, dato che l'entità non è un vault item); `MfaSetupService` scrive `MfaEnabled` alla conferma dell'attivazione TOTP. Login/logout/tenant provisioning erano già tracciati da Fase 0. Aggiunto in Fase 2 durante la revisione di sicurezza (vedi [security-model.md#stato-revisione-sicurezza](../security-model.md#stato-revisione-sicurezza), F-LOW-2): prima di questo passaggio queste mutazioni non lasciavano traccia in audit.
- Reveal di campi sensibili: il server non vede mai il contenuto, quindi non può osservare da solo quando un campo viene mostrato. Nuovo evento `Revealed` + endpoint esplicito `POST /api/vaults/{vaultId}/items/{itemId}/reveal`, che il client (quando esisterà) dovrà richiamare al click su "mostra".
- `RefreshTokenService` scrive `SessionsRevoked` anche quando rileva il riuso di un refresh token già ruotato (indizio di furto/compromissione), non solo su revoca esplicita dell'utente — vedi F-INFO-1 nella revisione di sicurezza.
- `ChangeMasterPasswordService` scrive il nuovo `MasterPasswordChanged` al cambio riuscito della master password (vedi [authentication.md](authentication.md)); un tentativo con la password attuale sbagliata non viene tracciato, coerente con `ConfirmTotpAsync`/`MfaEnabled` che logga solo l'attivazione riuscita, non ogni tentativo fallito.
- `EmailOtpRequested`/`EmailOtpVerified`/`EmailOtpFailed` (scaffoldati da Fase 0) sono ora scritti da `EmailVerificationService` per la verifica email in registrazione (vedi [authentication.md](authentication.md)); a differenza di `ChangeMasterPasswordService`, qui anche i tentativi falliti vengono tracciati (`EmailOtpFailed`), perché un codice ha un numero massimo di tentativi da esaurire prima che serva richiederne uno nuovo. Nessuna voce viene scritta per un'email sconosciuta (anti-enumeration, stesso principio del login). Questi stessi tre eventi sono pensati per essere riusati anche dal futuro fattore MFA Email OTP (Fase 3), da cui il nome generico.
- Lettura: `GET /api/audit` (filtri `action`, `from`, `to`, `skip`, `take`) tramite `IAuditLogService`. Visibilità secondo [roles-permissions.md](roles-permissions.md): Admin vede tutte le voci del tenant, Operator solo le proprie. SuperAdmin escluso da questo endpoint — l'audit di piattaforma è parte della Dashboard SuperAdmin, non ancora implementata.
- Ogni voce referenzia solo `VaultItemId` (mai il contenuto); il titolo/nome della voce, essendo dentro `EncryptedPayload`, va risolto lato client dopo decifratura per costruire messaggi tipo "Password 'GitHub' modificata".
- Vista utente "Attività recenti" (Blazor): `Pages/Activity.razor` (`/activity`), tabella paginata (skip/take, 50 per pagina) con filtro per tipo di azione, sopra `GET /api/audit` tramite il nuovo `AuditApiClient`. Nessuna modifica lato server: l'endpoint scopa già i risultati per ruolo, quindi la pagina non ha logica specifica per Admin/Operator. Deliberatamente **non** risolve `VaultItemId` in un titolo decifrato (niente "Password 'GitHub' modificata", solo azione/timestamp/IP/user agent) — già utile per rilevare accessi anomali, la risoluzione del titolo resta un possibile miglioramento futuro se servisse davvero. Verificato dal vivo in un browser reale: login, creazione di una voce, voci `LoginSuccess`/`Created` visualizzate con etichette in italiano corrette, filtro per azione verificato funzionante. Nessun nuovo test dedicato (lavoro solo `Web.Client`); 379 test invariati e verdi.
- Retention configurabile: nuovo `IAuditLogRetentionService`/`AuditLogRetentionService` (`CffVaultManager.Infrastructure.Audit`) elimina le voci più vecchie della finestra configurata (`AuditLog:RetentionDays`, default 90 giorni se assente) tramite `PurgeExpiredEntriesAsync`, attraversando tutti i tenant (incluse le voci di piattaforma con `TenantId` nullo — la retention è una politica operativa/di storage, non una scelta per-tenant). Le entità vengono materializzate prima del confronto sul timestamp, stesso motivo di `AuditLogService.ListAsync`: il provider SQLite usato nei test non traduce confronti relazionali su `DateTimeOffset` in SQL. Un nuovo `AuditLogRetentionHostedService : BackgroundService` lo esegue una volta all'avvio e poi ogni 24h per tutta la vita del processo (self-hosted a singola istanza, nessuno scheduler distribuito necessario), risolvendo il servizio scoped da un nuovo `IServiceScope` a ogni tick. Deliberatamente **non** implementata l'archiviazione (spostamento su storage freddo prima della cancellazione): non esiste ancora un'infrastruttura di archiviazione in questo progetto e aggiungerne una solo per questo sarebbe feature non necessaria (v2 se servisse davvero). 4 nuovi test Infrastructure (389 in totale nella solution).
- Da fare: notifica email per eventi critici (v2, collegato a [notifications.md](notifications.md)) — già in parte coperto dagli alert di sicurezza in notifications.md.
