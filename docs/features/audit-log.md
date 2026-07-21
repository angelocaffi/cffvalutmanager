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
- Lettura: `GET /api/audit` (filtri `action`, `from`, `to`, `skip`, `take`) tramite `IAuditLogService`. Visibilità secondo [roles-permissions.md](roles-permissions.md): Admin vede tutte le voci del tenant, Operator solo le proprie. SuperAdmin escluso da questo endpoint — l'audit di piattaforma è parte della Dashboard SuperAdmin, non ancora implementata.
- Ogni voce referenzia solo `VaultItemId` (mai il contenuto); il titolo/nome della voce, essendo dentro `EncryptedPayload`, va risolto lato client dopo decifratura per costruire messaggi tipo "Password 'GitHub' modificata".
- Da fare: vista utente "Attività recenti" (Blazor), retention/rotazione configurabile (default 90 giorni, poi archiviazione), notifica email per eventi critici (v2, collegato a [notifications.md](notifications.md)).
