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

Da pianificare.
