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

- Scrittura eventi: `AuditLogEntry` (già esistente da Fase 0) viene ora popolata anche per le azioni sul vault — `VaultItemService` scrive `Created`/`Viewed`/`Updated`/`Deleted` (soft-delete) per ogni voce; `MfaSetupService` scrive `MfaEnabled` alla conferma dell'attivazione TOTP. Login/logout/tenant provisioning erano già tracciati da Fase 0.
- Reveal di campi sensibili: il server non vede mai il contenuto, quindi non può osservare da solo quando un campo viene mostrato. Nuovo evento `Revealed` + endpoint esplicito `POST /api/vaults/{vaultId}/items/{itemId}/reveal`, che il client (quando esisterà) dovrà richiamare al click su "mostra".
- Lettura: `GET /api/audit` (filtri `action`, `from`, `to`, `skip`, `take`) tramite `IAuditLogService`. Visibilità secondo [roles-permissions.md](roles-permissions.md): Admin vede tutte le voci del tenant, Operator solo le proprie. SuperAdmin escluso da questo endpoint — l'audit di piattaforma è parte della Dashboard SuperAdmin, non ancora implementata.
- Ogni voce referenzia solo `VaultItemId` (mai il contenuto); il titolo/nome della voce, essendo dentro `EncryptedPayload`, va risolto lato client dopo decifratura per costruire messaggi tipo "Password 'GitHub' modificata".
- Da fare: vista utente "Attività recenti" (Blazor), retention/rotazione configurabile (default 90 giorni, poi archiviazione), notifica email per eventi critici (v2, collegato a [notifications.md](notifications.md)).
