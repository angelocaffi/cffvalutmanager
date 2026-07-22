# Notifiche

> Stato: alert di sicurezza via email implementati (vedi sezione Stato in fondo). Password compromesse: **decisione presa** — nessuna notifica email, solo dashboard in-app (vedi [password-health.md](password-health.md)), per non far mai transitare verso il server nemmeno il metadato "questa voce è compromessa". Notifica di scadenza carta **scartata** (non solo rimandata): vedi [../security-model.md](../security-model.md#gestione-carte-di-credito--considerazioni-aggiuntive).

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

Alert di sicurezza via email implementati, scoped deliberatamente a ciò che il server può osservare da solo. Scadenza carte è stata invece **scartata definitivamente**, non rimandata: vedi [../security-model.md](../security-model.md#gestione-carte-di-credito--considerazioni-aggiuntive) — qualunque meccanismo per farla osservare al server richiederebbe un campo non cifrato con la data di scadenza, in contrasto diretto col principio di zero-knowledge.

`ISecurityNotificationService`/`SecurityNotificationService` (riusa `IEmailSender`), agganciato come dipendenza opzionale (default `null`, stesso pattern di `IEmailVerificationService?` su `ProvisionTenantService`) a:
- `AuthenticationService.IssueSessionAsync`: alert solo al primo login riuscito da un indirizzo IP mai visto prima per quell'account (verificato contro `AuditLogEntries` prima di scrivere la voce del login corrente, cosi il controllo non vede mai se stesso).
- `ChangeMasterPasswordService`: alert a ogni cambio master password riuscito.
- `EmailOtpMfaService.DisableAsync` / `WebAuthnService.RemoveCredentialAsync`: alert che nomina il fattore/dispositivo disattivato.

6 nuovi test in `AuthenticationTests.cs` (385 in totale nella solution). Verificato anche dal vivo contro l'Api reale (non solo i servizi costruiti direttamente nei test): due login dallo stesso IP hanno prodotto esattamente una riga di log di notifica, confermando che la registrazione DI in `ServiceCollectionExtensions` risolve correttamente end-to-end.

**Password compromesse**: decisione presa — nessun canale email/server per questo evento (a differenza degli alert sopra, che il server osserva da solo). Il client esegue il controllo HIBP interamente in locale e mostra l'esito solo nella dashboard `/password-health` (vedi [password-health.md](password-health.md)): nessun round-trip al server, nemmeno per un flag di metadato "voce compromessa". Scelta esplicita rispetto all'alternativa (un endpoint che riceve solo "questa voce è compromessa" e fa scattare un'email generica) per non introdurre alcuna osservabilità server-side su quali voci sono a rischio.

**Provider email reale**: `IEmailSender` è ora davvero collegato via SMTP (`SmtpEmailSender`, `CffVaultManager.Infrastructure/Authentication/SmtpEmailSender.cs`, libreria MailKit) invece del solo `LoggingEmailSender` — scelta deliberata di SMTP generico anziché l'API di un vendor specifico (SendGrid/Postmark/ecc.): quasi ogni servizio email transazionale espone comunque un endpoint SMTP, quindi una sola implementazione copre tutti questi provider tramite configurazione (sezione `Email` in `appsettings.json`), senza legare il progetto a un SDK/account cloud specifico — coerente con la natura self-hosted di questo progetto. Se `Email:SmtpHost` non è configurato (stringa vuota, stesso pattern già in uso per `WebAuthn:RelyingPartyId`), la DI ricade su `LoggingEmailSender` così un ambiente di sviluppo locale non richiede un account SMTP solo per avviare l'app. Nessun retry/coda: fuori scope per un singolo relay self-hosted. 3 nuovi test unitari (`SmtpEmailSenderTests.cs`, con un fake scritto a mano di una piccola interfaccia di trasporto interna — non l'intera `ISmtpClient` di MailKit, troppo ampia per un fake senza libreria di mocking) verificano la costruzione del messaggio, l'autenticazione saltata per un relay anonimo, e la propagazione di un errore di invio.

Da fare: canali oltre email per gli alert esistenti (push/in-app). Scadenza carta e notifica password compromesse non sono più in scope come canale email (vedi sopra).
