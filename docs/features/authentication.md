# Autenticazione e master password

## Scopo

Garantire che solo il legittimo proprietario di un vault possa sbloccarlo, senza che il server debba mai conoscere la master password in chiaro.

## Requisiti funzionali

- Registrazione utente: email + master password (con verifica robustezza minima: lunghezza, entropia stimata).
- Login: email + master password → derivazione client-side della KEK → sblocco DEK → sessione autenticata.
- **Logout esplicito e auto-lock** dopo N minuti di inattività (configurabile dall'utente, default 15 min).
- **Cambio master password**: richiede la password attuale, ri-cifra solo la DEK (vedi [encryption-key-management.md](encryption-key-management.md)).
- **Recupero accesso**: senza master password non è possibile recuperare i dati (per design zero-knowledge). Meccanismo opzionale di "recovery kit" — design formalizzato, vedi sezione dedicata sotto.
- **MFA (Multi-Factor Authentication)**:
  - Fattori supportati:
    - **TOTP** (RFC 6238, Google Authenticator/Authy compatibile) — baseline, fattore consigliato.
    - **Email OTP** (codice one-time inviato via email) — fattore aggiuntivo o alternativo al TOTP, **non sostitutivo**. Strutturalmente più debole del TOTP perché il canale email non è sotto controllo esclusivo dell'app/utente (vedi Requisiti di sicurezza).
    - **WebAuthn/Passkey (autenticazione biometrica)** — Windows Hello, Touch ID/Face ID, sblocco biometrico Android: qualunque platform authenticator il browser/dispositivo espone via WebAuthn. **Requisito esplicito per il frontend Blazor Web.Client, da non dimenticare quando si costruisce la schermata di login**: il form di accesso deve riservare fin dal primo disegno UI un pulsante/opzione "Accedi con biometria" quando `navigator.credentials` + un platform authenticator sono disponibili (rilevabile via `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`), con fallback silenzioso e trasparente a master password + TOTP sui device che non la supportano — mai un vicolo cieco se la biometria non è disponibile. Implementato lato server (entità `WebAuthnCredential`, una per dispositivo) — vedi "Stato" sotto. Manca ancora il pulsante "Accedi con biometria" e il flusso client-side in `Web.Client`.
  - Un utente può registrare uno o più fattori. Quando ne ha più di uno, **sceglie quale fattore usare al login**; è possibile impostare un fattore predefinito configurabile dall'utente (usato automaticamente salvo scelta esplicita di un altro).
  - MFA richiesta al login, non solo alla registrazione.
  - **Vincolo zero-knowledge**: nessun fattore MFA — in particolare l'Email OTP — sostituisce mai la master password né bypassa il flusso di login. La master password è l'unico input che deriva la KEK lato client; un OTP via email **non produce alcuna chiave crittografica** e viene sempre verificato *in aggiunta* all'inserimento della master password, mai al suo posto. Non è previsto alcun login "passwordless" via Email OTP.
- **Logout remoto**: possibilità di invalidare tutte le sessioni attive (es. in caso di sospetta compromissione).

### Verifica email in registrazione

Flusso distinto dall'MFA (attiva l'account, non protegge un login già autenticato) ma che riusa la **stessa infrastruttura di generazione/invio del codice one-time**:

- Al termine della registrazione viene inviato all'indirizzo dichiarato un codice one-time; l'account resta in stato non verificato finché il codice non è confermato.
- Stesse garanzie di sicurezza dell'Email OTP MFA (codice generato con RNG crittografico, scadenza breve, monouso, hash a riposo, rate limiting).
- Confermare l'email **non** abilita di per sé l'Email OTP come fattore MFA: sono due configurazioni separate.

> Nota: questo flusso post-hoc (l'account esiste già, poi si verifica) resta invariato per `UserRegistrationService` (utenti aggiunti da un Admin a un tenant esistente). Il **self-service tenant signup** pubblico (`Register.razor`) invece **non** lo usa più: la verifica avviene *prima* che Tenant/Admin esistano, tramite un gate a due fasi dedicato — vedi [../multi-tenancy.md](../multi-tenancy.md#provisioning-di-un-nuovo-tenant).

### Email OTP come fattore MFA

- L'utente abilita esplicitamente l'Email OTP nelle impostazioni di sicurezza; l'indirizzo usato è quello dell'account.
- Al login, se l'Email OTP è il fattore scelto, il sistema invia il codice e richiede all'utente di inserirlo dopo la verifica della master password.
- Se l'utente ha registrato sia TOTP sia Email OTP, la UI segnala l'Email OTP come opzione **"meno sicura"** rispetto al TOTP.

### Recovery kit

Design completo (meccanismo, prova di possesso lato server, MFA-gating, invalidazione) in [../security-model.md](../security-model.md#recovery-kit) — qui solo il riepilogo lato utente/prodotto.

- **Opt-in**, generato dalla pagina `/security` (non in registrazione): l'utente genera una Recovery Key a 256 bit, mostrata **una sola volta**, con un avviso esplicito di salvarla offline (non recuperabile in seguito).
- Per recuperare l'accesso: email + Recovery Key → se l'utente ha MFA attivo va comunque verificato → l'utente sceglie una nuova master password → tutte le sessioni attive vengono revocate e viene inviata una notifica di sicurezza (email + in-app), stesso comportamento già in vigore per il cambio master password.
- **Monouso**: un kit si consuma dopo un recupero riuscito. Va rigenerato anche dopo una rotazione DEK (`/api/auth/rotate-dek`), che lo invalida automaticamente — la UI di `/security` deve mostrare chiaramente lo stato (nessun kit / kit attivo dal \[data\] / kit invalidato, rigeneralo).
- Non implementato ancora: design formalizzato, in attesa di piano di implementazione.

### Recovery MFA via email (backlog v2)

- Idea: usare l'Email OTP come **fallback di recovery** quando l'utente perde il device TOTP.
- **Funzionalità rischiosa e NON prevista in v1** (backlog v2): un canale di recovery via email indebolisce l'intera protezione MFA se abusato — chi controlla la casella email può aggirare il secondo fattore. Se implementata, va accompagnata da controlli aggiuntivi (conferma multi-step, notifiche, finestre temporali, audit rafforzato) e resta comunque subordinata all'inserimento della master password.

## Requisiti di sicurezza

- Nessuna master password trasmessa o loggata in chiaro oltre il singolo scambio TLS necessario al login (se verifica lato server) — preferibile derivazione e verifica interamente client-side.
- Rate limiting su tentativi di login (es. exponential backoff, lockout temporaneo dopo N tentativi falliti).
- MFA secret cifrato a riposo.
- **Email OTP / codici one-time**:
  - Codice numerico di 6-8 cifre generato con RNG crittografico (`RandomNumberGenerator`).
  - **Scadenza breve** (5-10 minuti) e **monouso**: invalidato dopo il primo utilizzo con successo o dopo N tentativi falliti.
  - **Hash a riposo**: il codice è persistito solo come hash, mai in chiaro nel database, nei log o presso il provider email oltre l'invio stesso.
  - **Rate limiting**: cooldown sul reinvio (es. 60s) e numero massimo di tentativi di verifica (es. 5), oltre il quale scatta un lockout temporaneo.
  - **Anti-enumeration**: risposta uniforme all'utente indipendentemente dal fatto che l'indirizzo email esista o meno nel sistema.
  - Audit log di richiesta, verifica e fallimento del codice, **mai del contenuto del codice stesso**.
- Vedi checklist completa in [../security-model.md](../security-model.md).

## UX essenziale

- Schermata di sblocco separata dalla navigazione principale (analoga a Bitwarden/1Password): finché il vault non è sbloccato, nessun dato è visibile né richiesto al server.
- Indicatore di forza della master password in fase di registrazione/cambio.
- Timer visibile o notifica prima dell'auto-lock.
- Per i codici one-time (Email OTP e verifica email): campo dedicato all'inserimento del codice, **countdown di scadenza** visibile e pulsante di **reinvio con cooldown** mostrato (il pulsante resta disabilitato finché il cooldown non è trascorso).
- Se l'utente ha più fattori MFA registrati, selettore del fattore al login con l'Email OTP etichettato come opzione "meno sicura" rispetto al TOTP.
- **Biometria**: se il device/browser espone un platform authenticator, un pulsante "Accedi con biometria" ben visibile accanto (non al posto di) al form master password + TOTP, con icona coerente col tipo di sensore quando rilevabile (impronta/volto/generico). Nessun messaggio di errore bloccante se la biometria non è disponibile o l'utente la annulla — semplice ritorno al flusso standard.

## Stato

Login (con risoluzione tenant), MFA TOTP e ora rate limiting/lockout sono implementati ed esposti su `/api/auth/*`. Decisione Blazor WASM confermata ([../architecture.md](../architecture.md)).

**Rate limiting su tentativi di login** — due livelli indipendenti, entrambi necessari (proteggono minacce diverse):

- **Lockout per account**: `User.FailedLoginAttempts`/`LockedUntil`. Dopo 5 tentativi consecutivi falliti (password o codice MFA errati — condividono lo stesso contatore, perché entrambi indicano un attacco in corso contro lo stesso account) l'account viene bloccato per 15 minuti a finestra fissa (non estesa da ulteriori tentativi durante il blocco). Il contatore si azzera su login riuscito. Un tentativo con codice MFA errato conta quanto uno con password errata: un attaccante che ha già superato il controllo password sta comunque provando a indovinare un codice a 6 cifre, banale da forzare senza questo limite.
- **Rate limiting per IP**: limiter a finestra fissa (`Microsoft.AspNetCore.RateLimiting`, nessun pacchetto esterno) su `/api/auth/login`, `/api/auth/mfa/verify`, `/api/auth/refresh` — 10 richieste al minuto per IP, nessuna coda (l'attaccante non guadagna nulla dall'essere messo in coda). Protegge l'endpoint da un singolo chiamante che prova email diverse, scenario che il lockout per-account da solo non copre.

8 nuovi test (6 lockout in `AuthenticationTests`, 2 rate limiting in `RateLimitingTests`).

**Logout remoto** — `IRefreshTokenService` espone `ListActiveSessionsAsync`/`RevokeSessionAsync`/`RevokeAllSessionsAsync`, su `GET/POST /api/auth/sessions*`. Ogni riga `RefreshToken` attiva (non revocata, non scaduta) rappresenta una sessione/dispositivo distinto; la revoca (singola o totale) impedisce il rinnovo futuro tramite `/refresh`, ma **non invalida un access token JWT già emesso** — essendo stateless, un JWT non può essere revocato singolarmente senza una blocklist server-side dedicata (fuori scope v1); la finestra residua è comunque limitata ai 15 minuti di vita dell'access token, stessa scelta accettata già fatta per la sospensione tenant. Azione tracciata con `AuditAction.SessionsRevoked`. 12 nuovi test (7 Infrastructure + 5 Api).

Totale: 293 test nella solution. Manca ancora: verifica email in registrazione, cambio master password (Fase 2), Email OTP come fattore MFA (Fase 3), WebAuthn/Passkey biometrico (Fase 3 lato server; il vincolo di design UI — riservare posto per l'opzione biometrica nella schermata di login — vale invece da subito, non aspettare la Fase 3, per non doverla reinserire forzatamente in un'interfaccia già disegnata senza pensarci).

**Revisione di sicurezza (Fase 2)** — vedi [security-model.md#stato-revisione-sicurezza](../security-model.md#stato-revisione-sicurezza) per il dettaglio completo. Tocca direttamente questa feature: il login per email sconosciuta ora paga sempre lo stesso costo Argon2id di una password errata su un account esistente (anti-enumeration, F-MED-1); `RefreshTokenService` ora revoca l'intera catena di refresh token discendenti quando rileva il riuso di un token già ruotato, non solo il tentativo di riuso stesso (F-INFO-1); `POST /api/tenants` ha ora rate limiting e un 409 pulito su slug/email duplicati invece di un 500 (F-LOW-1). Totale: 298 test nella solution.

**Cambio master password** — `POST /api/auth/change-master-password` (autenticato), `IChangeMasterPasswordService`/`ChangeMasterPasswordService`. Coerente col principio "ri-cifra solo la DEK" di [../security-model.md](../security-model.md): il client sblocca la DEK con la vecchia KEK, deriva una nuova KEK dalla nuova master password (nuovo salt, eventualmente nuovi parametri Argon2id), ri-wrappa la stessa DEK con la nuova KEK e manda al server solo `NewEncryptedDek`/`NewMasterPasswordSalt`/nuovi parametri KDF — nessun vault item viene mai ri-cifrato. `CurrentAuthHash` prova il possesso della master password attuale (verificato con lo stesso `IAuthHashHasher` usato al login); un hash errato ritorna `401` senza modificare nulla. Al successo, `IRefreshTokenService.RevokeAllSessionsAsync` invalida **tutte** le sessioni attive, incluso il chiamante corrente: un refresh token rimasto valido non servirebbe comunque a un attaccante senza la nuova master password, ma forzare la ri-autenticazione ovunque è la difesa in profondità attesa per un'operazione così sensibile (stesso schema di "logout remoto" già sopra). Azione tracciata con il nuovo `AuditAction.MasterPasswordChanged`. 3 nuovi test Infrastructure (`AuthenticationTests`) + 2 nuovi test end-to-end con crypto reale in `CryptoRoundTripTests` (che verificano anche che un vault item creato prima del cambio resti decifrabile, provando che la sua cifratura non viene mai toccata). Totale: 305 test nella solution.

**Verifica email in registrazione** — riusa l'entità `OneTimeCode` (scaffoldata da Fase 0, mai usata finora) e gli `AuditAction` `EmailOtpRequested`/`EmailOtpVerified`/`EmailOtpFailed` (scaffoldati sempre da Fase 0, pensati per essere condivisi con il futuro fattore MFA Email OTP di Fase 3). Un codice numerico a 6 cifre viene generato e inviato automaticamente alla fine di `ProvisionTenantService.ProvisionAsync` e `UserRegistrationService.RegisterInTenantAsync` — entrambi ora prendono una dipendenza opzionale `IEmailVerificationService?` (default `null`, sul modello del default opzionale già usato da `ServerAuthHashHasher`), così nessuno dei test esistenti che costruiscono questi servizi direttamente ha dovuto cambiare. Nuova colonna `User.EmailVerifiedAt` (migration `AddUserEmailVerification`, su/giù verificati).

Due endpoint pubblici (l'utente potrebbe non poter ancora fare login), entrambi anti-enumeration e rate-limitati come gli altri endpoint auth pubblici:

- `POST /api/auth/email-verification/resend` — sempre `202`, che l'email esista o meno, sia già verificata o il reinvio sia ancora dentro il cooldown di 60s: solo in nessuno di questi casi viene davvero generato e inviato un nuovo codice.
- `POST /api/auth/email-verification/confirm` — `204` se il codice è corretto, altrimenti `401`, identico sia per email inesistente sia per codice sbagliato/scaduto/con tentativi esauriti (max 5 per codice, scadenza 10 minuti).

Il codice è hashato a riposo con HMAC-SHA256 salato per record, non Argon2id: a differenza dell'auth hash o del refresh token, è un valore a bassa entropia (6 cifre) ma anche a vita brevissima — le difese reali contro il brute force sono la scadenza, il limite tentativi per codice e il rate limiting IP sull'endpoint, non un hash costoso che rallenterebbe solo i tentativi legittimi senza un reale beneficio contro chi ha già una copia della riga con l'hash.

Nessun provider email reale è ancora collegato: `IEmailSender`/`LoggingEmailSender` sono un placeholder che logga l'intento di invio (destinatario e oggetto, mai il corpo/il codice) senza consegnare realmente nulla — va sostituito con un provider SMTP/transazionale reale prima di qualunque rilascio in produzione (vedi [encryption-key-management.md](encryption-key-management.md) per la stessa cautela applicata alla crittografia).

7 nuovi test Infrastructure (`AuthenticationTests`) + 5 nuovi test end-to-end (`EmailVerificationEndpointsTests`, inclusi i due endpoint pubblici e il loro comportamento anti-enumeration). Totale: 317 test nella solution.

**Email OTP come fattore MFA** — `IEmailOtpMfaService`/`EmailOtpMfaService`, che riusa `OneTimeCode` con `OtpPurpose.MfaLogin` e lo stesso schema di hashing di "Verifica email in registrazione" (estratto in `OneTimeCodeHasher`, condiviso dai due servizi). Due endpoint autenticati per abilitare/disabilitare il fattore: `POST /api/auth/mfa/email-otp/enable` (richiede `User.EmailVerifiedAt` valorizzato — altrimenti `409`, non ha senso abilitare l'invio di codici a un indirizzo mai verificato — e non prevede un passo di conferma separato come il TOTP, perché non c'è un secret da provare in possesso: l'indirizzo è già verificato) e `POST /api/auth/mfa/email-otp/disable`.

`User.MfaEnabled` (TOTP) e `User.MfaEmailOtpEnabled` sono ora entrambi controllati al login: `LoginResult.MfaRequired` porta la lista `AvailableMfaFactors` (uno o entrambi), così il client sa quali fattori offrire. A differenza del TOTP — il cui codice vive già sul device dell'utente — l'Email OTP richiede un invio esplicito: `POST /api/auth/mfa/email-otp/send` (solo il challenge token come identità, risposta uniforme `202` anche se l'utente non ha questo fattore abilitato — no-op interno in quel caso) genera e spedisce il codice per la sfida in corso. `POST /api/auth/mfa/verify` accetta ora anche un campo `Factor` (`Totp` di default, o `EmailOtp`); un codice sbagliato per un fattore mai abilitato dall'utente fallisce sempre, anche se il challenge esiste (perché un *altro* fattore era abilitato). Il fallimento di un codice Email OTP conta verso lo stesso lockout per-account del TOTP e della password (stesso principio già in vigore).

Deliberatamente **non** implementato: un "fattore predefinito" persistito lato server (il doc lo descrive come possibile UX) — con la lista `AvailableMfaFactors` già esposta, quale fattore preselezionare è una scelta puramente client-side, senza bisogno di una colonna server dedicata.

9 nuovi test Infrastructure (`AuthenticationTests`) + 6 nuovi test end-to-end (`EmailOtpMfaEndpointsTests`). Totale: 341 test nella solution.

**WebAuthn/Passkey biometrico (lato server)** — `IWebAuthnService`/`WebAuthnService`, che delega interamente la crittografia CBOR/COSE/attestazione/asserzione a [Fido2NetLib](https://github.com/passwordless-lib/fido2-net-lib) (pacchetto `Fido2`) invece di reimplementarla: stesso principio già seguito per Argon2id (Konscious) e TOTP (Otp.NET). Due nuove entità: `WebAuthnCredential` (una per dispositivo registrato — a differenza di TOTP/Email OTP non esiste un flag on/off singolo, la disponibilità del fattore è "l'utente ha almeno una credenziale") e `WebAuthnCeremony` (stato effimero tra "begin" e "complete" di una cerimonia, stesso pattern a riga-breve di `OneTimeCode`).

Endpoint autenticati per la gestione dispositivi: `POST /api/auth/webauthn/register/begin`, `POST .../register/complete` (con nickname opzionale), `GET /api/auth/webauthn/credentials`, `POST .../credentials/{id}/remove`. Endpoint pubblici per il login, sullo stesso modello di Email OTP: `POST /api/auth/webauthn/assertion/begin` (richiede solo il challenge token; `401` se non valido) e `POST .../assertion/complete` (sfrutta `IAuthenticationService.VerifyWebAuthnAsync`, un metodo dedicato invece di riusare `VerifyMfaAsync` perché il payload è un oggetto JSON strutturato, non un codice breve). `LoginResult.AvailableMfaFactors` ora può includere anche `WebAuthn`.

RP ID/Origins sono configurabili (`WebAuthn:RelyingPartyId`/`WebAuthn:ServerName`/`WebAuthn:Origins`) e devono corrispondere all'host **Web(.Client)** che il browser carica, non a questa Api (stesso genere di distinzione già presente per CORS). Nessun `IMetadataService`: essendo un deployment self-hosted a singolo tenant applicativo, non serve la FIDO Metadata Service per un allow-list di modelli di authenticator.

Verificato con un "authenticator virtuale" nei test (`FakeWebAuthnAuthenticator`, ECDSA P-256, formato di attestazione "none") che genera risposte realmente firmate — necessario perché non c'è un browser reale nei test per guidare `navigator.credentials`, ma la crittografia di Fido2NetLib viene comunque esercitata per intero, non solo aggirata con un mock. Ha permesso di scoprire (e correggere) due bug reali prima ancora di un test manuale: (1) `ListCredentialsAsync` ordinava per `DateTimeOffset` lato SQL, non supportato da SQLite (stesso difetto già visto altrove, stesso fix: materializzare poi ordinare in memoria); (2) una firma corrotta può far lanciare a Fido2NetLib un'eccezione diversa da `Fido2VerificationException` (osservato: `ArgumentOutOfRangeException` dal suo decoder ASN.1) — trattandosi di CBOR/ASN.1 completamente sotto controllo di un chiamante non fidato, il servizio ora cattura qualunque eccezione da quel punto (non solo il tipo "atteso"), altrimenti un assertion/attestation malformato avrebbe prodotto un 500 non gestito invece di un rifiuto pulito.

19 nuovi test (10 Infrastructure incluso il round-trip crittografico reale + 5 Api; 358 in totale nella solution).

**WebAuthn/Passkey (lato `Web.Client`)** — nuovo modulo JS (`wwwroot/js/webauthn.js`, il primo JS interop di questo progetto) che guida le vere chiamate `navigator.credentials.create()`/`get()`: converte solo i campi byte (challenge, user.id, id delle credenziali) tra base64url e `ArrayBuffer`, perché il resto del JSON prodotto da Fido2NetLib combacia già uno a uno con la forma richiesta dal browser. `Login.razor` mostra il fattore nel selettore MFA ("Chiave di sicurezza o impronta/volto"), con avvio automatico della cerimonia se è l'unico fattore registrato (stesso pattern già usato per l'invio automatico dell'Email OTP). Nuova sezione in `/security` per registrare (con nickname opzionale), elencare e rimuovere dispositivi — nessun toggle singolo, essendo la disponibilità del fattore "esiste almeno una credenziale".

Verificato dal vivo in un browser reale, non solo compilato: usando l'authenticator virtuale WebAuthn di Chromium (via Chrome DevTools Protocol, `WebAuthn.addVirtualAuthenticator` con presence simulation automatica) sono stati eseguiti realmente `navigator.credentials.create()`/`get()` — crittografia reale, non un mock — attraverso l'intero flusso: registrazione di un dispositivo, login completato tramite l'asserzione WebAuthn auto-innescata, rimozione del dispositivo, e login che torna a non richiedere MFA una volta rimossa l'ultima credenziale.

Nello stesso lavoro, corretto un bug preesistente scoperto toccando `Login.razor`: il KEK in memoria (necessario per sbloccare la DEK dopo la verifica MFA) veniva azzerato incondizionatamente nel blocco `finally` dopo *ogni* tentativo di verifica MFA, incluso uno fallito — un TOTP o Email OTP digitato male una sola volta rispediva quindi silenziosamente l'utente alla schermata email/master password, invece di permettere ulteriori tentativi fino al lockout dell'account già previsto lato server (5 tentativi). Ora il KEK viene azzerato solo al login completato con successo o alla chiusura del componente, mai su un singolo tentativo fallito.
