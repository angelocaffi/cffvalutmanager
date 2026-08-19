# Multi-tenancy

Questo documento definisce come CffVaultManager isola più organizzazioni (tenant) sulla stessa infrastruttura, i ruoli utente e le implicazioni di scalabilità. È vincolante quanto [security-model.md](security-model.md): ogni feature che tocca dati utente deve rispettare l'isolamento per tenant descritto qui.

## Concetti

- **Tenant** (organizzazione): unità di isolamento primaria. Ogni azienda/cliente che usa CffVaultManager è un tenant separato. Un tenant contiene i propri utenti, vault, voci, cartelle e audit log.
- **SuperAdmin**: utente di piattaforma, non appartiene a nessun tenant specifico. Gestisce il ciclo di vita dei tenant (creazione, sospensione, eliminazione), il provisioning e il supporto, ma **non ha e non può avere** accesso in chiaro ai secrets di alcun tenant — coerente con il principio zero-knowledge.
- **Admin** (di tenant): amministra utenti, ruoli e impostazioni all'interno del proprio tenant. Non ha automaticamente accesso ai vault personali degli operatori (vedi sotto "Admin e vault personali").
- **Operator**: utente standard di un tenant, con accesso al proprio vault personale ed eventualmente a vault condivisi dell'organizzazione secondo i permessi assegnati.

## Ruoli — riepilogo

| Ruolo | Scope | Accesso ai secrets |
|---|---|---|
| SuperAdmin | Globale, cross-tenant | Nessuno — solo metadati amministrativi (nome tenant, numero utenti, stato abbonamento, audit di sistema) |
| Admin | Singolo tenant | Solo i propri secrets personali + eventuali vault condivisi a cui è stato esplicitamente invitato (chiave asimmetrica, vedi [features/sharing-access-control.md](features/sharing-access-control.md)) |
| Operator | Singolo tenant | Solo i propri secrets personali + eventuali vault condivisi a cui è stato esplicitamente invitato |

Dettagli funzionali dei ruoli in [features/roles-permissions.md](features/roles-permissions.md).

### Admin e vault personali

Un punto critico da preservare: **l'appartenenza a un tenant e il ruolo Admin non implicano accesso ai dati cifrati altrui**. Un Admin può:

- Creare/disabilitare utenti, assegnare ruoli, impostare policy (es. MFA obbligatoria, durata sessione).
- Vedere metadati (chi ha quante voci, ultimo accesso) tramite audit log — mai il contenuto.
- Accedere a un vault condiviso di organizzazione **solo** se incluso esplicitamente nella cifratura asimmetrica di quel vault (stesso meccanismo usato per la condivisione tra utenti).

Questo evita che "essere admin" diventi una backdoor implicita ai dati cifrati — coerente con [security-model.md](security-model.md).

## Strategia di isolamento dati

Approccio scelto: **database condiviso, schema condiviso, isolamento a livello di riga tramite colonna `TenantId`**.

Motivazione: rispetto a database-per-tenant o schema-per-tenant, questo modello scala meglio con un numero crescente di tenant di dimensioni piccole/medie (tipico di un vault SaaS), riduce il costo operativo (una sola istanza PostgreSQL da mantenere, patchare, backuppare) e si abbina bene a Entity Framework Core tramite **global query filters**.

Regole vincolanti:

- Ogni tabella che contiene dati appartenenti a un'organizzazione (`User` non-superadmin, `Vault`, `VaultItem`, `Folder`, `AuditLogEntry`, ecc.) ha una colonna `TenantId` **non nullable** e un indice composito che la include (es. `(TenantId, Id)`, `(TenantId, VaultId)`).
- **Global query filter EF Core** applicato a ogni `DbSet` tenant-scoped: `modelBuilder.Entity<T>().HasQueryFilter(e => e.TenantId == _currentTenant.TenantId)`. Nessuna query deve poter bypassare il filtro se non tramite un contesto amministrativo esplicito (vedi sotto).
- Il `TenantId` corrente è risolto **una volta per richiesta HTTP**, dal claim `tenant_id` nel JWT validato, mai da input utente (querystring, body, header arbitrario) — previene tenant spoofing.
- Le operazioni SuperAdmin che devono attraversare i tenant (es. dashboard di piattaforma) usano un `DbContext` o uno scope esplicito senza query filter, isolato in un servizio dedicato (`ITenantAdministrationService`) e mai riutilizzabile per leggere `EncryptedPayload`.
- Test di isolamento obbligatori: per ogni nuovo endpoint che legge/scrive dati tenant-scoped, un test che verifica che un JWT del tenant A non possa mai leggere/scrivere dati del tenant B, nemmeno conoscendo l'Id della risorsa (IDOR check).

## Risoluzione del tenant per richiesta

```
Richiesta HTTP → Middleware di autenticazione (valida JWT)
              → Middleware di risoluzione tenant (estrae tenant_id dal claim)
              → ITenantContext popolato per la durata della richiesta (scoped DI)
              → EF Core DbContext applica il query filter basato su ITenantContext
```

- Nessun servizio applicativo deve accettare un `TenantId` come parametro esplicito da fonti non fidate: `ITenantContext` è l'unica fonte di verità per la richiesta corrente.
- Il login iniziale (prima di avere un JWT con `tenant_id`) richiede che l'utente specifichi o venga risolto verso il proprio tenant (es. tramite l'email, che è univoca a livello di piattaforma, o tramite subdominio/slug organizzazione — da decidere in fase di UX).

## Provisioning di un nuovo tenant

Il provisioning self-service è **gated da verifica email**, non più un'unica chiamata pubblica che crea subito Tenant+Admin. Motivazione: `POST /api/tenants` pubblico era finora protetto solo dal rate limiting per IP — nessun controllo impediva la creazione massiva incontrollata di organizzazioni ("chiunque si crea la propria organizzazione senza controllo"). Il gate risolve questo e apre contestualmente un punto naturale dove, in futuro, inserire la selezione di un piano a pagamento.

### Flusso in due fasi

1. **Richiesta** — `POST /api/tenants/requests` (pubblico, rate-limitato come oggi `POST /api/tenants`). Il client genera il materiale crittografico esattamente come nel flusso attuale (salt, KEK via Argon2id con i parametri di produzione, DEK generata e wrappata — tutto lato client, il server riceve solo byte opachi) e invia in un'unica sottomissione:
   - **Dati organizzazione**: nome, slug desiderato.
   - **Email amministratore** + materiale crypto opaco (`AuthHash`, `EncryptedDek`, `MasterPasswordSalt`, parametri KDF) — stessa forma di `ProvisionTenantRequest` oggi, invariata.
   - **Dati anagrafici/fatturazione** (in chiaro, mai un secret — vedi [security-model.md](security-model.md#dati-di-fatturazione-provisioning-tenant)): ragione sociale o nome e cognome, tipo soggetto (privato/azienda), indirizzo di fatturazione, Partita IVA e/o Codice Fiscale, Codice Destinatario SDI o PEC (fatturazione elettronica italiana), telefono opzionale.

   Il server esegue lo stesso controllo proattivo di univocità slug/email di oggi, poi persiste una riga **pending** `TenantProvisioningRequest` (vedi [data-model.md](data-model.md#tenantprovisioningrequest-staging-non-tenant-scoped--il-tenant-non-esiste-ancora)) con un codice di verifica — stesso schema anti-bruteforce di `OneTimeCode` (hash HMAC-SHA256 salato, scadenza, tentativi massimi, cooldown di reinvio). **Nessun Tenant/User viene ancora creato.** Il codice è inviato via email (stesso canale di [features/notifications.md](features/notifications.md)).

2. **Conferma** — `POST /api/tenants/requests/confirm` (pubblico, rate-limitato, anti-enumeration: stessa risposta uniforme per email sconosciuta/codice errato/già confermato, sul modello di `IEmailVerificationService.ConfirmAsync`). Solo con un codice valido e non scaduto, il server esegue **atomicamente** ciò che oggi fa `ProvisionTenantService.ProvisionAsync` — crea Tenant, primo utente Admin, vault personale "Personale", audit `TenantProvisioned` — più una nuova riga `TenantBillingProfile` (vedi [data-model.md](data-model.md#tenantbillingprofile-tenant-scoped-11-con-tenant)) popolata con i dati anagrafici raccolti allo step 1. La `TenantProvisioningRequest` viene eliminata alla conferma; se non confermata entro la finestra di validità (es. 24h — più ampia di un normale OTP, l'utente potrebbe controllare la mail più tardi) scade e viene ripulita periodicamente (stesso pattern di `AuditLogRetentionHostedService`).

Un SuperAdmin può ancora creare un tenant direttamente, senza passare dalla richiesta pubblica gated (onboarding assistito/supporto) — riusa internamente lo stesso `IProvisionTenantService` invocato dallo step 2 del flusso pubblico.

### Cosa NON cambia

- L'invariante "ogni `User` non-SuperAdmin appartiene a esattamente un Tenant": nessun utente "orfano" esiste mai a database — la riga `User` nasce solo alla conferma (step 2), già con il proprio `TenantId`. `TenantProvisioningRequest` non è un tenant né uno user, è solo uno stato di richiesta in attesa.
- Lo zero-knowledge: il materiale crittografico (`AuthHash`/`EncryptedDek`/salt/parametri KDF) resta identico a oggi, solo persistito temporaneamente in una riga pending invece che direttamente su `User` — il server non lo decifra né lo interpreta in nessuno dei due flussi.
- Il modello di isolamento tenant, i query filter, la risoluzione tenant per richiesta (sezioni sopra).

### Dati di fatturazione — riuso futuro

I dati anagrafici raccolti allo step 1 sono lo scopo esplicito di questo gate oltre alla verifica email: renderli disponibili senza doverli richiedere una seconda volta quando in futuro verrà introdotto un piano a pagamento — selezione piano, addebito e generazione fattura potranno leggere `TenantBillingProfile` senza un nuovo modulo di raccolta dati. **Fuori scope in questa fase**: l'integrazione con un processore di pagamento (da decidere) e la generazione effettiva di ricevute/fatture — qui si formalizzano solo il modello dati e il punto del flusso in cui i dati vengono raccolti.

L'integrazione di pagamento è ora formalizzata separatamente in [features/billing.md](features/billing.md): il tenant nasce sempre gratuito con 30 giorni di prova (`Tenant.TrialEndsAt`), il pagamento (PayPal, singolo, non ricorrente) avviene **dopo** il provisioning da un Admin già autenticato, non durante il signup.

## Scalabilità

- **API**: stateless, scalabile orizzontalmente dietro load balancer (nessuna sessione in-memory grazie a JWT + refresh token).
- **PostgreSQL**: partenza con istanza singola; colonna `TenantId` presente ovunque fin dall'inizio rende possibile in futuro:
  - Partizionamento orizzontale per `TenantId` (table partitioning) se un singolo tenant cresce molto.
  - Migrazione di tenant enterprise "rumorosi" verso un database dedicato (stessa struttura, connection string diversa risolta da `ITenantContext`) senza riscrivere la logica applicativa.
- **Indicizzazione**: ogni indice su tabelle tenant-scoped deve avere `TenantId` come prima colonna, per garantire che le query restino efficienti anche con milioni di righe totali distribuite su molti tenant.
- **Rate limiting e quote**: da applicare per tenant (non solo per utente), per evitare che un tenant rumoroso degradi il servizio per gli altri.

## Cosa NON deve succedere

- Una query che legge `VaultItem` senza passare da un `DbContext` con query filter attivo (rischio concreto se si usa SQL raw/Dapper in futuro: va sempre filtrato esplicitamente per `TenantId`).
- Un endpoint che accetta `tenantId` dal client e lo usa per decidere quali dati restituire, invece di derivarlo dal JWT.
- Un ruolo Admin/SuperAdmin che, tramite un "impersona utente" o strumento di supporto, ottiene accesso al vault decifrato di un utente senza il consenso esplicito di quest'ultimo (e comunque mai alla master password).
