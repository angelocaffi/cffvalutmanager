# Gestione password

## Scopo

Funzionalità core di un password manager: memorizzazione sicura e generazione di credenziali per siti/servizi.

## Requisiti funzionali

- CRUD voce password: Titolo, Username/Email, Password **[cifrato]**, URL, Note **[cifrato]**.
- **Generatore di password**: lunghezza configurabile, set di caratteri (maiuscole/minuscole/numeri/simboli), esclusione caratteri ambigui, opzione passphrase (parole).
- **Cronologia password**: mantenere le versioni precedenti di una password quando viene aggiornata, per riferimento (utile se un servizio esterno non ha ancora recepito il cambio).
- Associazione a più URL per la stessa voce (es. login/sso su più domini dello stesso servizio).
- Indicatore forza password (calcolato client-side, mai inviato al server in chiaro).

## Requisiti di sicurezza

- La password non è mai visibile di default nella lista; richiede azione esplicita ("mostra"/copia).
- Il generatore usa un RNG crittograficamente sicuro, mai `Random` standard.
- La cronologia password è cifrata con la stessa DEK della voce corrente.

## UX essenziale

- Pulsante "genera password" integrato nel form di creazione/modifica.
- Copia rapida username/password con feedback visivo e auto-clear appunti.
- Eventuale badge "password debole" o "riutilizzata" — collegato a [password-health.md](password-health.md) (v2).

## Stato

Da pianificare.
