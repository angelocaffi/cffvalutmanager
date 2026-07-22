# Notifiche

> Stato: alert di sicurezza via email implementati (vedi sezione Stato in fondo); password compromesse resta backlog (v2). Notifica di scadenza carta **scartata** (non solo rimandata): vedi [../security-model.md](../security-model.md#gestione-carte-di-credito--considerazioni-aggiuntive).

## Scopo

Avvisare l'utente di eventi rilevanti per la sicurezza o la manutenzione del vault.

## Requisiti funzionali (proposta)

- Notifica di sicurezza: nuovo login da dispositivo/IP sconosciuto, cambio master password, disattivazione MFA — vedi [audit-log.md](audit-log.md).
- Notifica opzionale su password compromesse rilevate (collegata a [password-health.md](password-health.md), se implementata).
- Canali: email come baseline; notifiche push/in-app in versioni successive.

## Requisiti di sicurezza

- Il contenuto delle notifiche non deve mai includere il secret stesso (es. "La tua password per GitHub è scaduta" sì, il valore della password no).
- Le email di sicurezza vanno inviate anche se l'utente non è loggato (es. alert di login sospetto), tramite servizio email transazionale dedicato, senza esporre dati del vault nel corpo del messaggio oltre al minimo necessario.

## Stato

Alert di sicurezza via email implementati, scoped deliberatamente a ciò che il server può osservare da solo. Password compromesse resta backlog (vive solo nel payload cifrato — richiederebbe che il client stesso comunichi al server cosa monitorare, una scelta di design separata, non ancora presa). Scadenza carte è stata invece **scartata definitivamente**, non rimandata: vedi [../security-model.md](../security-model.md#gestione-carte-di-credito--considerazioni-aggiuntive) — qualunque meccanismo per farla osservare al server richiederebbe un campo non cifrato con la data di scadenza, in contrasto diretto col principio di zero-knowledge.

`ISecurityNotificationService`/`SecurityNotificationService` (riusa `IEmailSender`, oggi `LoggingEmailSender` — nessun provider reale ancora collegato, vedi [authentication.md](authentication.md)), agganciato come dipendenza opzionale (default `null`, stesso pattern di `IEmailVerificationService?` su `ProvisionTenantService`) a:
- `AuthenticationService.IssueSessionAsync`: alert solo al primo login riuscito da un indirizzo IP mai visto prima per quell'account (verificato contro `AuditLogEntries` prima di scrivere la voce del login corrente, cosi il controllo non vede mai se stesso).
- `ChangeMasterPasswordService`: alert a ogni cambio master password riuscito.
- `EmailOtpMfaService.DisableAsync` / `WebAuthnService.RemoveCredentialAsync`: alert che nomina il fattore/dispositivo disattivato.

6 nuovi test in `AuthenticationTests.cs` (385 in totale nella solution). Verificato anche dal vivo contro l'Api reale (non solo i servizi costruiti direttamente nei test): due login dallo stesso IP hanno prodotto esattamente una riga di log di notifica, confermando che la registrazione DI in `ServiceCollectionExtensions` risolve correttamente end-to-end.

Da fare: notifica password compromesse (richiede un meccanismo lato client, v2), canali oltre email (push/in-app). Scadenza carta non è più in scope (vedi sopra).
