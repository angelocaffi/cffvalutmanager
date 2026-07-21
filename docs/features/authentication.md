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
    - **WebAuthn/Passkey** — opzione avanzata (v2).
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

## Stato

Da pianificare — dipende dalla decisione Blazor Server vs WASM in [../architecture.md](../architecture.md).
