# Autenticazione e master password

## Scopo

Garantire che solo il legittimo proprietario di un vault possa sbloccarlo, senza che il server debba mai conoscere la master password in chiaro.

## Requisiti funzionali

- Registrazione utente: email + master password (con verifica robustezza minima: lunghezza, entropia stimata).
- Login: email + master password → derivazione client-side della KEK → sblocco DEK → sessione autenticata.
- **Logout esplicito e auto-lock** dopo N minuti di inattività (configurabile dall'utente, default 15 min).
- **Cambio master password**: richiede la password attuale, ri-cifra solo la DEK (vedi [encryption-key-management.md](encryption-key-management.md)).
- **Recupero accesso**: senza master password non è possibile recuperare i dati (per design zero-knowledge). Offrire eventualmente un meccanismo opzionale di "recovery kit" (chiave di recupero generata all'iscrizione, da salvare offline dall'utente) — da valutare in v2.
- **MFA (Multi-Factor Authentication)**:
  - Fattori supportati:
    - **TOTP** (RFC 6238, Google Authenticator/Authy compatibile) — baseline, fattore consigliato.
    - **Email OTP** (codice one-time inviato via email) — fattore aggiuntivo o alternativo al TOTP, **non sostitutivo**. Strutturalmente più debole del TOTP perché il canale email non è sotto controllo esclusivo dell'app/utente (vedi Requisiti di sicurezza).
    - **WebAuthn/Passkey (autenticazione biometrica)** — Windows Hello, Touch ID/Face ID, sblocco biometrico Android: qualunque platform authenticator il browser/dispositivo espone via WebAuthn. **Requisito esplicito per il frontend Blazor Web.Client, da non dimenticare quando si costruisce la schermata di login**: il form di accesso deve riservare fin dal primo disegno UI un pulsante/opzione "Accedi con biometria" quando `navigator.credentials` + un platform authenticator sono disponibili (rilevabile via `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`), con fallback silenzioso e trasparente a master password + TOTP sui device che non la supportano — mai un vicolo cieco se la biometria non è disponibile. Non ancora implementato lato server (serve una nuova entità per le credenziali WebAuthn registrate, analoga a `MfaSecret`) — vedi "Stato" sotto.
  - Un utente può registrare uno o più fattori. Quando ne ha più di uno, **sceglie quale fattore usare al login**; è possibile impostare un fattore predefinito configurabile dall'utente (usato automaticamente salvo scelta esplicita di un altro).
  - MFA richiesta al login, non solo alla registrazione.
  - **Vincolo zero-knowledge**: nessun fattore MFA — in particolare l'Email OTP — sostituisce mai la master password né bypassa il flusso di login. La master password è l'unico input che deriva la KEK lato client; un OTP via email **non produce alcuna chiave crittografica** e viene sempre verificato *in aggiunta* all'inserimento della master password, mai al suo posto. Non è previsto alcun login "passwordless" via Email OTP.
- **Logout remoto**: possibilità di invalidare tutte le sessioni attive (es. in caso di sospetta compromissione).

### Verifica email in registrazione

Flusso distinto dall'MFA (attiva l'account, non protegge un login già autenticato) ma che riusa la **stessa infrastruttura di generazione/invio del codice one-time**:

- Al termine della registrazione viene inviato all'indirizzo dichiarato un codice one-time; l'account resta in stato non verificato finché il codice non è confermato.
- Stesse garanzie di sicurezza dell'Email OTP MFA (codice generato con RNG crittografico, scadenza breve, monouso, hash a riposo, rate limiting).
- Confermare l'email **non** abilita di per sé l'Email OTP come fattore MFA: sono due configurazioni separate.

### Email OTP come fattore MFA

- L'utente abilita esplicitamente l'Email OTP nelle impostazioni di sicurezza; l'indirizzo usato è quello dell'account.
- Al login, se l'Email OTP è il fattore scelto, il sistema invia il codice e richiede all'utente di inserirlo dopo la verifica della master password.
- Se l'utente ha registrato sia TOTP sia Email OTP, la UI segnala l'Email OTP come opzione **"meno sicura"** rispetto al TOTP.

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
