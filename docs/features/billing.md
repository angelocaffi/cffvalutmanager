# Abbonamento e pagamento (PayPal)

## Scopo

Ogni tenant nasce gratuito con un periodo di prova di **30 giorni** dal provisioning. Allo scadere, se non ha effettuato un pagamento, il tenant passa in **sola lettura**: gli utenti possono ancora accedere e consultare/esportare i propri secrets, ma non possono più crearne o modificarne. Un pagamento singolo (non ricorrente) via **PayPal Checkout** sblocca **12 mesi** di accesso pieno a partire dalla scadenza corrente (se pagato in anticipo, i mesi si sommano a quelli residui, non ripartono da subito).

Questo documento formalizza il design richiesto prima dell'implementazione, per lo stesso motivo già seguito per [multi-tenancy.md#provisioning-di-un-nuovo-tenant](../multi-tenancy.md#provisioning-di-un-nuovo-tenant): tocca autorizzazione e tenancy, non solo una feature isolata.

## Fuori scope (esplicito)

- Rinnovo automatico/ricorrente (PayPal Subscriptions API) — solo pagamento singolo, ripetuto manualmente ogni anno.
- Più piani/tier o upselling — un solo piano a pagamento, prezzo fisso configurabile lato server.
- Generazione fattura reale/PDF — `TenantBillingProfile` (dati anagrafici già raccolti al provisioning) resta pronto per un futuro modulo fatturazione, non costruito qui.
- Webhook PayPal — la cattura è sincrona (l'utente resta nel flusso fino alla conferma); il webhook come rete di sicurezza per pagamenti approvati ma mai catturati (es. tab chiusa) è un miglioramento futuro, richiede un endpoint pubblico raggiungibile da PayPal (problema di per sé in sviluppo locale) — vedi "Limiti accettati" sotto.
- Rimborsi, dispute, contabilità.
- UI proattiva che disabilita i bottoni di scrittura lato client in modalità sola lettura — l'enforcement reale è server-side (vedi sotto); il client può mostrare un banner ma questo slice non copre il disabling capillare di ogni singolo bottone "crea/modifica".

## Modello dati

### `Tenant` (esteso)

Due nuovi campi non-nullable/nullable su `Tenant` (nessuna nuova entità 1:1 — sono dati di ciclo di vita del tenant stesso, letti ad ogni login/refresh, non anagrafica):

| Campo | Note |
|---|---|
| `TrialEndsAt` | `DateTimeOffset`, non-null. Impostato a `CreatedAt + 30 giorni` da `ProvisionTenantService.ProvisionAsync` alla creazione — nessuna migrazione dati per i tenant esistenti diversa da un default retroattivo (vedi "Migrazione" sotto). |
| `PlanExpiresAt` | `DateTimeOffset?`, null finché nessun pagamento è mai stato catturato. Impostato/esteso da ogni cattura riuscita: `PlanExpiresAt = (PlanExpiresAt is { } corrente && corrente > now ? corrente : now).AddDays(365)`. |

**Stato "sola lettura"** (calcolato, mai persistito come colonna separata): `IsReadOnly = now > TrialEndsAt && (PlanExpiresAt is null || now > PlanExpiresAt)`. SuperAdmin non è mai soggetto (non ha `TenantId`).

### `PaymentTransaction` **[tenant-scoped]** (nuova entità)

Traccia ogni tentativo di pagamento, a scopo di audit/idempotenza e come base per una futura ricevuta.

| Campo | Note |
|---|---|
| Id | GUID |
| TenantId | FK a Tenant |
| CreatedByUserId | FK a User — chi ha iniziato il pagamento (solo `Admin`, vedi sotto) |
| PayPalOrderId | Id ordine restituito da PayPal, indice univoco (idempotenza: la cattura verifica prima se un ordine già `Captured` esiste) |
| Amount / Currency | importo e valuta **decisi lato server** al momento della creazione ordine, mai accettati dal client (vedi "Sicurezza" sotto) |
| Status | enum `PaymentTransactionStatus`: `Created`, `Captured`, `Failed` |
| CreatedAt | |
| CapturedAt | nullable |
| PlanExpiresAtAfterCapture | copia dello stato risultante di `Tenant.PlanExpiresAt` al momento della cattura — storico immutabile anche se il piano cambia dopo (utile in futuro per una ricevuta) |

Nessun nuovo valore `AuditAction` oltre a `PaymentCaptured` (i tentativi falliti restano visibili tramite `PaymentTransaction.Status`, non serve duplicarli in audit — coerente con l'obiettivo di non aggiungere tracciamento ridondante).

## Flusso API

### Perché "upgrade post-provisioning" e non durante il signup

Il gate di provisioning (`POST /api/tenants/requests` → `confirm`) resta invariato: il tenant nasce sempre gratuito/in trial. L'Admin, già autenticato, avvia il pagamento da una pagina dedicata quando vuole. Questo evita di intrecciare la crittografia client-side del signup (già delicata) con una chiamata a un processore di pagamento esterno prima che un `User`/JWT esista.

### Endpoint (`src/CffVaultManager.Api/Endpoints/BillingEndpoints.cs`, nuovo, gruppo `/api/billing`, `RequireAuthorization()`)

| Endpoint | Ruolo | Descrizione |
|---|---|---|
| `GET /api/billing/status` | qualunque ruolo di tenant | `{ PlanName, TrialEndsAt, PlanExpiresAt, IsReadOnly }` — per il banner/pagina |
| `POST /api/billing/checkout` | solo `Admin` | Crea un ordine PayPal (importo/valuta/piano fissi da configurazione server, es. `Billing:AnnualPrice`/`Billing:Currency`/`Billing:PlanName`), persiste `PaymentTransaction` (`Status = Created`), ritorna `{ OrderId }` da passare al PayPal JS SDK |
| `POST /api/billing/checkout/{orderId}/capture` | solo `Admin` | Cattura l'ordine presso PayPal, verifica `COMPLETED`, aggiorna `PaymentTransaction` ed estende `Tenant.PlanExpiresAt` in un'unica transazione, scrive `AuditAction.PaymentCaptured`. Idempotente: se `orderId` risulta già `Captured` localmente, ritorna lo stesso risultato senza richiamare PayPal né estendere una seconda volta |

Solo `Admin` può avviare/completare un pagamento (coerente con `multi-tenancy.md`: "Admin amministra... impostazioni" a livello di organizzazione) — un `Operator` può solo vedere `GET /api/billing/status`.

### Integrazione PayPal (server-to-server, Orders API v2)

Nuova astrazione `IPayPalClient` (`Infrastructure/Billing/PayPalClient.cs`, `internal sealed`, `HttpClient` tipizzato con `AddHttpClient`, base address sandbox `https://api-m.sandbox.paypal.com` da configurazione — passaggio a live in futuro è solo un cambio di base address/credenziali, non di codice):

1. `GetAccessTokenAsync` — OAuth2 client-credentials (`POST /v1/oauth2/token`, Basic Auth con `PayPal:ClientId`/`PayPal:ClientSecret`), token cacheato in memoria fino a poco prima della sua scadenza dichiarata (~9h), un solo refresh condiviso per tutta l'istanza (singleton), non per richiesta.
2. `CreateOrderAsync(amount, currency)` → `POST /v2/checkout/orders` (`intent: CAPTURE`), ritorna l'`id` ordine.
3. `CaptureOrderAsync(orderId)` → `POST /v2/checkout/orders/{id}/capture`, ritorna stato (`COMPLETED`/altro) e l'id di cattura.

**Nessun credential store "no-op" come per `LoggingEmailSender`**: non esiste un fallback sicuro per i pagamenti. Se `PayPal:ClientId`/`Secret` non sono configurati, `POST /api/billing/checkout` ritorna `503 Service Unavailable` con un messaggio esplicito — nessuna chiamata PayPal viene tentata.

## Enforcement sola lettura

**Decisione**: il flag calcolato non richiede una query DB per ogni richiesta. Viene valutato una volta al login/refresh (`AuthenticationService.IssueSessionAsync`/`RefreshAsync`, stesso punto dove oggi si controlla `IsTenantSuspendedAsync`) e incorporato come claim opzionale nell'access token (`IJwtTokenService.CreateAccessToken`, nuovo parametro `bool isReadOnly = false` → claim `tenant_read_only = "true"` solo se true, stesso pattern del claim opzionale `tenant_id`).

Conseguenza accettata: se un pagamento viene catturato mentre un access token è già stato emesso, il claim resta "vecchio" fino al prossimo refresh (access token vive `AccessTokenLifetime`, oggi pochi minuti) — il frontend forza un refresh subito dopo una cattura riuscita per non far aspettare l'utente fino alla scadenza naturale.

Un nuovo `IEndpointFilter` (`Api/Authorization/ReadOnlyEnforcementFilter.cs`) applicato solo ai gruppi che scrivono contenuto di vault — `VaultsEndpoints`, `VaultItemsEndpoints`, `FoldersEndpoints`, `TagsEndpoints`, `VaultMembershipsEndpoints`, `ItemMembershipEndpoints`, `ExternalShareLinkEndpoints` — **non** a `AuthEndpoints`/`BillingEndpoints`/`NotificationEndpoints`/`AuditEndpoints`/`AdminEndpoints` (un tenant scaduto deve poter comunque pagare, leggere notifiche, cambiare master password, fare logout). Il filtro lascia passare sempre `GET`/`HEAD`; per ogni altro metodo, se il claim `tenant_read_only` è presente, ritorna **`402 Payment Required`** (più semantico di 403 per questo caso specifico) prima di eseguire l'handler.

## Sicurezza

- **L'importo non è mai un input del client**: `POST /api/billing/checkout` non accetta importo/valuta nel body — legge sempre `Billing:AnnualPrice`/`Billing:Currency` da configurazione server. Altrimenti un client malevolo potrebbe creare un ordine PayPal per €0,01 e ottenere comunque l'estensione di 365 giorni.
- **Client Secret mai al client**: solo `PayPal:ClientId` (pubblico per design — è l'unico modo in cui l'SDK JS di PayPal funziona) raggiunge `Web.Client` (`appsettings.json`, valore non sensibile). `PayPal:ClientSecret` resta in `user-secrets`/variabili d'ambiente lato Api, mai servito in alcuna risposta HTTP verso il client.
- **Idempotenza della cattura**: un doppio click su "Paga" o un retry di rete non deve estendere il piano due volte — controllo su `PaymentTransaction.Status` prima di richiamare PayPal.
- **Nessun impatto sullo zero-knowledge**: nessun dato di pagamento (importo, PayPalOrderId, stato) è un secret applicativo — stessa classe di fiducia già stabilita per `TenantBillingProfile` in [security-model.md](../security-model.md#dati-di-fatturazione-provisioning-tenant). Non richiede nuova crittografia.
- **Query filter**: `PaymentTransaction` è tenant-scoped come tutto il resto — stesso query filter EF Core, stesso obbligo di test IDOR (vedi [multi-tenancy.md](../multi-tenancy.md)).

## Flusso Web.Client

Nuova pagina `Pages/Billing.razor` (`/billing`, `[Authorize]`, link in `MainLayout.razor`):

1. Al caricamento, chiama `GET /api/billing/status` e mostra: piano corrente, giorni residui di trial o data di scadenza piano, banner rosso "sola lettura" se `IsReadOnly`.
2. Se non in trial attivo né già pagato per l'anno in corso, mostra i **PayPal Smart Buttons**: nuovo script `wwwroot/js/paypal-buttons.js` che carica l'SDK PayPal (`<script src="https://www.paypal.com/sdk/js?client-id={ClientId}&currency=EUR">`, `ClientId` letto da `appsettings.json`) e chiama `paypal.Buttons({...}).render(...)`:
   - `createOrder` → invoca (via `IJSObjectReference`/`DotNetObjectReference`) `BillingApiClient.CreateCheckoutAsync()` → ritorna l'`OrderId` da passare a PayPal.
   - `onApprove(data)` → invoca `BillingApiClient.CaptureAsync(data.orderID)` → in caso di successo, forza un refresh del token (`AuthApiClient.RefreshAsync`, già esistente per `TokenRefreshScheduler`) per far cadere subito il claim `tenant_read_only`, poi ricarica lo stato pagina.
   - `onError` → mostra un messaggio d'errore, nessun cambio di stato.
3. Nessun redirect a pagina esterna: l'approvazione avviene nel popup gestito dall'SDK PayPal stesso (comportamento standard "Smart Buttons"), non serve gestire `return_url`/`cancel_url` lato nostro.

## Migrazione (tenant esistenti)

I tenant creati prima di questa feature non hanno `TrialEndsAt`. Migration EF Core con backfill dati: per ogni riga esistente, `TrialEndsAt = CreatedAt + 30 giorni` (se già nel passato, il tenant passa immediatamente in sola lettura al primo login successivo alla migrazione — accettato, sono solo tenant di sviluppo/test in questo momento, nessun tenant di produzione reale esiste ancora).

## Test previsti

- Infrastructure: calcolo `IsReadOnly` (trial attivo/scaduto, piano attivo/scaduto, rinnovo che estende da scadenza corrente vs da oggi), `PayPalClient` con `HttpMessageHandler` fittizio (nessuna vera chiamata di rete nei test automatici), idempotenza cattura doppia, isolamento tenant su `PaymentTransaction` (IDOR).
- Api: round-trip `checkout` → `capture` con `IPayPalClient` sostituito da un fake nei test (stesso principio già usato per `IEmailSender` nei test esistenti), 402 su scrittura con claim `tenant_read_only`, 200 su lettura con lo stesso claim, 503 se PayPal non configurato, solo `Admin` può chiamare `checkout`/`capture`.

## Verifica dal vivo (sandbox PayPal)

Prerequisito: app PayPal Developer sandbox (Client ID/Secret) e un account sandbox "Personal" (buyer di test) — vedi istruzioni fornite in chat. Flusso di verifica: login come Admin di un tenant in sola lettura (trial forzato scaduto in dev) → `/billing` → bottone PayPal → login con l'account sandbox Personal nel popup → approvazione → cattura confermata lato nostro → banner sola lettura sparito → scrittura di un vault item torna a funzionare.
