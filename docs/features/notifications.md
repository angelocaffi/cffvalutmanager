# Notifiche

> Stato: alert di sicurezza via email **e** in-app implementati (vedi sezione Stato in fondo). Password compromesse: **decisione presa** — nessuna notifica email, solo dashboard in-app (vedi [password-health.md](password-health.md)), per non far mai transitare verso il server nemmeno il metadato "questa voce è compromessa". Notifica di scadenza carta **scartata** (non solo rimandata): vedi [../security-model.md](../security-model.md#gestione-carte-di-credito--considerazioni-aggiuntive).

## Scopo

Avvisare l'utente di eventi rilevanti per la sicurezza o la manutenzione del vault.

## Requisiti funzionali (proposta)

- Notifica di sicurezza: nuovo login da dispositivo/IP sconosciuto, cambio master password, disattivazione MFA — vedi [audit-log.md](audit-log.md).
- Notifica opzionale su password compromesse rilevate (collegata a [password-health.md](password-health.md), se implementata).
- Canali: email e in-app implementati (vedi sezione Stato); push OS-level (Web Push/VAPID) resta una fase futura, non costruita in questa sessione.

## Requisiti di sicurezza

- Il contenuto delle notifiche non deve mai includere il secret stesso (es. "La tua password per GitHub è scaduta" sì, il valore della password no).
- Le email di sicurezza vanno inviate anche se l'utente non è loggato (es. alert di login sospetto), tramite servizio email transazionale dedicato, senza esporre dati del vault nel corpo del messaggio oltre al minimo necessario.

## Stato

Alert di sicurezza via email e in-app implementati, scoped deliberatamente a ciò che il server può osservare da solo. Scadenza carte è stata invece **scartata definitivamente**, non rimandata: vedi [../security-model.md](../security-model.md#gestione-carte-di-credito--considerazioni-aggiuntive) — qualunque meccanismo per farla osservare al server richiederebbe un campo non cifrato con la data di scadenza, in contrasto diretto col principio di zero-knowledge.

`ISecurityNotificationService`/`SecurityNotificationService` (riusa `IEmailSender`), agganciato come dipendenza opzionale (default `null`, stesso pattern di `IEmailVerificationService?` su `ProvisionTenantService`) a:
- `AuthenticationService.IssueSessionAsync`: alert solo al primo login riuscito da un indirizzo IP mai visto prima per quell'account (verificato contro `AuditLogEntries` prima di scrivere la voce del login corrente, cosi il controllo non vede mai se stesso).
- `ChangeMasterPasswordService`: alert a ogni cambio master password riuscito.
- `EmailOtpMfaService.DisableAsync` / `WebAuthnService.RemoveCredentialAsync`: alert che nomina il fattore/dispositivo disattivato.

6 nuovi test in `AuthenticationTests.cs` (385 in totale nella solution). Verificato anche dal vivo contro l'Api reale (non solo i servizi costruiti direttamente nei test): due login dallo stesso IP hanno prodotto esattamente una riga di log di notifica, confermando che la registrazione DI in `ServiceCollectionExtensions` risolve correttamente end-to-end.

**Password compromesse**: decisione presa — nessun canale email/server per questo evento (a differenza degli alert sopra, che il server osserva da solo). Il client esegue il controllo HIBP interamente in locale e mostra l'esito solo nella dashboard `/password-health` (vedi [password-health.md](password-health.md)): nessun round-trip al server, nemmeno per un flag di metadato "voce compromessa". Scelta esplicita rispetto all'alternativa (un endpoint che riceve solo "questa voce è compromessa" e fa scattare un'email generica) per non introdurre alcuna osservabilità server-side su quali voci sono a rischio.

**Provider email reale**: `IEmailSender` è ora davvero collegato via SMTP (`SmtpEmailSender`, `CffVaultManager.Infrastructure/Authentication/SmtpEmailSender.cs`, libreria MailKit) invece del solo `LoggingEmailSender` — scelta deliberata di SMTP generico anziché l'API di un vendor specifico (SendGrid/Postmark/ecc.): quasi ogni servizio email transazionale espone comunque un endpoint SMTP, quindi una sola implementazione copre tutti questi provider tramite configurazione (sezione `Email` in `appsettings.json`), senza legare il progetto a un SDK/account cloud specifico — coerente con la natura self-hosted di questo progetto. Se `Email:SmtpHost` non è configurato (stringa vuota, stesso pattern già in uso per `WebAuthn:RelyingPartyId`), la DI ricade su `LoggingEmailSender` così un ambiente di sviluppo locale non richiede un account SMTP solo per avviare l'app. Nessun retry/coda: fuori scope per un singolo relay self-hosted. 3 nuovi test unitari (`SmtpEmailSenderTests.cs`, con un fake scritto a mano di una piccola interfaccia di trasporto interna — non l'intera `ISmtpClient` di MailKit, troppo ampia per un fake senza libreria di mocking) verificano la costruzione del messaggio, l'autenticazione saltata per un relay anonimo, e la propagazione di un errore di invio.

**Canale in-app**: nuova entità dedicata `Notification` (non un riuso di `AuditLogEntry`, che mescola troppi tipi di evento e non ha stato letto/non letto) — `Id, TenantId, UserId, Type (NewLoginFromUnknownIp | MasterPasswordChanged | MfaFactorDisabled), Message, CreatedAt, ReadAt`. `SecurityNotificationService` scrive una riga `Notification` agli stessi 3 trigger che generano già l'email, tramite `INotificationService`/`NotificationService` (`CffVaultManager.Infrastructure/Authentication/NotificationService.cs`) — nessuna modifica ai 4 chiamanti esterni (`AuthenticationService`, `ChangeMasterPasswordService`, `EmailOtpMfaService`, `WebAuthnService`). Sia l'invio email sia la creazione della notifica sono avvolti in try/catch dentro `SecurityNotificationService`: un fallimento logga un warning e non propaga mai, per rispettare il contratto già documentato su `ISecurityNotificationService` ("una notifica non deve mai far fallire l'operazione che l'ha generata") — contratto che prima non era davvero enforced da nessun try/catch, e che una verifica dal vivo contro SQL Server ha mostrato non bastare da solo: un insert fallito restava tracciato sul `DbContext` scoped condiviso con il resto della request e faceva fallire anche il `SaveChangesAsync` successivo (es. l'emissione del refresh token). `NotificationService.CreateAsync` ora fa il detach esplicito dell'entità in caso di eccezione, così un fallimento della notifica resta isolato.

Api: `GET /api/notifications`, `GET /api/notifications/unread-count`, `POST /api/notifications/{id}/read`, `POST /api/notifications/read-all` (`NotificationEndpoints.cs`), tutti autenticati e scoped al chiamante.

Web.Client: icona a campanella in `MainLayout.razor` (componente `Shared/NotificationBell.razor`) con badge del conteggio non letti, aggiornato a ogni cambio di route (`NavigationManager.LocationChanged`, nessun SignalR — coerente con l'assenza di infrastruttura realtime nel progetto); il click apre un dropdown con le notifiche recenti e un bottone "Segna tutte come lette". Verificato dal vivo in browser: login da un nuovo tenant → badge a 1 → dropdown con il messaggio corretto → "Segna tutte come lette" azzera il badge.

Nuovi test: `NotificationServiceTests.cs` (5), 3 nuovi test in `AuthenticationTests.cs` (collegamento ai 3 trigger), `NotificationEndpointsTests.cs` (6, end-to-end via HTTP). 481 test in totale nella solution.

**Push OS-level (Web Push/VAPID)**: deliberatamente non costruito in questa sessione. Richiederebbe trasformare l'app in una PWA (manifest + service worker) da zero — infrastruttura enorme e architetturalmente delicata per un'app di sicurezza (un service worker intercetta tutte le richieste di rete). Resta una fase futura descritta ma non implementata.

Da fare: push OS-level (vedi sopra). Scadenza carta e notifica password compromesse non sono più in scope come canale email (vedi sopra).
