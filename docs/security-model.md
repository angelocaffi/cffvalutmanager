# Modello di sicurezza

Questo documento definisce il modello di minaccia e le scelte crittografiche vincolanti per il progetto. Qualunque implementazione che tocchi autenticazione, cifratura o storage di secrets deve rispettare quanto descritto qui.

## Modello di minaccia

Il sistema deve proteggere i dati da:

1. **Compromissione del database**: un attaccante con accesso completo al DB non deve poter leggere password, numeri di carta o secrets in chiaro.
2. **Compromissione del server applicativo** (parziale): idealmente il server non gestisce mai la master password né la DEK in chiaro (obiettivo zero-knowledge; dipende dalla decisione Blazor Server vs WASM in [architecture.md](architecture.md)).
3. **Intercettazione di rete**: mitigata con TLS obbligatorio (HSTS, no downgrade).
4. **Credential stuffing / brute force**: rate limiting su login, lockout progressivo, MFA.
5. **Accesso fisico/malware sul client**: fuori scope primario, ma mitigato da timeout di sessione e cifratura in memoria dove possibile.
6. **Accesso cross-tenant (IDOR)**: un utente autenticato di un tenant non deve mai poter leggere/scrivere dati di un altro tenant, nemmeno conoscendo o indovinando l'identificativo di una risorsa. Vedi [multi-tenancy.md](multi-tenancy.md) per la strategia di isolamento.
7. **Escalation di privilegio interna**: un Admin o SuperAdmin non deve poter usare il proprio ruolo per accedere ai secrets in chiaro di altri utenti, in assenza di condivisione esplicita basata su crittografia asimmetrica. "Essere amministratore" non deve mai equivalere a "poter decifrare i dati altrui".
8. **Compromissione della casella email dell'utente**: quando l'Email OTP è abilitato come fattore MFA, il canale email diventa parte della superficie d'attacco. Un attaccante che controlla la casella email dell'utente **e** ne conosce la master password non è bloccato dall'Email OTP da solo — per questo l'Email OTP è considerato più debole del TOTP e non deve mai essere l'unica barriera oltre la master password né sostituirla (vedi [features/authentication.md](features/authentication.md)).

Fuori scope (v1): protezione da attaccante con accesso root persistente al client dell'utente, attacchi side-channel avanzati.

## Gerarchia delle chiavi

```
Master Password (utente, mai salvata)
      │  Argon2id (salt unico per utente, parametri calibrati)
      ▼
Key Encryption Key (KEK)      — derivata, mai persistita
      │  cifra
      ▼
Data Encryption Key (DEK)     — generata random per utente, persistita SOLO cifrata con la KEK
      │  cifra (AES-256-GCM, nonce univoco per record)
      ▼
Singoli secrets (password, carte, note) — persistiti come ciphertext + nonce + tag
```

- **Derivazione**: Argon2id (preferito) o PBKDF2-HMAC-SHA256 con almeno 600.000 iterazioni come fallback se Argon2id non disponibile nello stack .NET scelto.
- **Cifratura simmetrica**: AES-256-GCM per autenticazione integrata (previene tampering silenzioso).
- **Salt e nonce**: unici per record, generati con RNG crittograficamente sicuro (`RandomNumberGenerator` in .NET), mai riutilizzati.
- **Rotazione DEK**: supportare la rotazione della DEK senza richiedere il cambio della master password (re-cifratura batch dei secrets con nuova DEK).
- **Cambio master password**: deve ri-cifrare solo la DEK (non tutti i secrets), rendendo l'operazione economica.

## Autenticazione

- Login basato su verifica della master password lato client dove possibile (o hash Argon2id lato server come fallback se Blazor Server), mai confrontando la password in chiaro salvata.
- **MFA obbligatoria consigliata** per l'accesso al vault: TOTP (RFC 6238) come baseline, WebAuthn/passkey come opzione avanzata.
- **Email OTP** disponibile come fattore MFA aggiuntivo/alternativo al TOTP (mai sostitutivo della master password). Da trattare come fattore **più debole**: il canale email non è sotto controllo esclusivo dell'app/utente, quindi un attaccante che compromette la casella email indebolisce la protezione. L'Email OTP non deriva alcuna chiave e non bypassa il login zero-knowledge. Requisiti operativi (scadenza breve, monouso, hash a riposo, rate limiting, anti-enumeration) in [features/authentication.md](features/authentication.md).
- Sessioni con timeout configurabile e "auto-lock" dopo inattività (analogo al lock di un password manager desktop).
- Token di sessione (JWT) a vita breve + refresh token con rotazione; refresh token revocabile lato server (logout remoto da tutti i dispositivi).

## Logging e osservabilità

- **Divieto assoluto**: loggare password, numeri di carta, CVV, contenuto di secrets o master password, in qualunque forma (anche mascherata parzialmente, salvo ultime 4 cifre carte dove esplicitamente richiesto dalla UX).
- Audit log delle *azioni* (chi ha letto/creato/modificato/eliminato quale voce, quando), mai del *contenuto*. Vedi [features/audit-log.md](features/audit-log.md).
- Log applicativi (errori, performance) devono passare da uno scrubber che rifiuta payload con pattern noti di secrets prima della scrittura.

## Gestione carte di credito — considerazioni aggiuntive

- Se in futuro si integrano pagamenti reali, valutare la conformità **PCI-DSS**; per un vault "personal", i dati carta sono trattati come qualunque altro secret cifrato, mai trasmessi a processori di pagamento.
- Il PAN (numero carta) va sempre mascherato in UI di default (mostra ultime 4 cifre), con "reveal" esplicito che richiede ri-autenticazione o conferma.

## Eccezione controllata: controllo password compromesse (k-anonymity)

Il password health check (vedi [features/password-health.md](features/password-health.md)) introduce l'unica chiamata di rete di questo progetto indirettamente legata a un secret: `IBreachCheckService`/`HibpBreachCheckService` (in `CffVaultManager.Crypto`, eseguito solo client-side) invia ai server di *Have I Been Pwned* i primi 5 caratteri esadecimali dell'hash SHA-1 della password — mai la password né l'hash completo, seguendo il protocollo k-anonymity dell'API stessa. SHA-1 qui non è una scelta di sicurezza di questo progetto (che usa Argon2id/AES-256-GCM ovunque il rischio sia reale): è l'hash su cui è indicizzato il corpus HIBP, mandato dal loro protocollo. Il prefisso a 5 caratteri non è invertibile alla password originale (spazio di ricerca ancora enorme). Nessun altro servizio esterno riceve mai dati derivati da un secret in questo progetto.

## Checklist di revisione sicurezza (da applicare a ogni feature che tocca secrets)

- [ ] Il dato sensibile è cifrato prima di toccare il livello di persistenza?
- [ ] Chiavi/nonce sono generati con RNG sicuro e mai riutilizzati?
- [ ] Nessun log, eccezione o messaggio di errore espone il contenuto del secret?
- [ ] L'endpoint è protetto da autenticazione e autorizzazione (ownership del secret)?
- [ ] L'azione è tracciata in audit log (senza contenuto sensibile)?
- [ ] La query passa da un `DbContext`/repository con query filter per `TenantId` attivo (vedi [multi-tenancy.md](multi-tenancy.md))?
- [ ] Il `TenantId` usato è derivato dal JWT/`ITenantContext`, mai da un parametro fornito dal client?
- [ ] Un ruolo Admin/SuperAdmin che tocca questa feature non ottiene accesso implicito a secrets altrui?
- [ ] Se la feature genera codici OTP via email, il codice è persistito solo come hash (mai in chiaro), con scadenza breve, uso singolo, rate limiting (cooldown reinvio + tentativi massimi) e risposta anti-enumeration uniforme? Il codice non compare mai in log o audit.

## Stato revisione sicurezza

**2026-07-21**: prima revisione completa dell'intera codebase contro questa checklist e il modello di minaccia sopra (Fase 2 roadmap), con approccio adversariale (non un semplice check a spunta). Riscontrati e risolti:

- **F-HIGH-1**: un Admin dello stesso tenant ma non membro di un vault organizzativo poteva auto-invitarsi o revocare membri (`VaultMembershipService.InviteAsync`/`RevokeAsync` verificavano solo `TenantId`, non l'appartenenza effettiva). Corretto riusando `VaultAccessGuard.GetAccessibleVaultAsync` come unico punto di verifica esistenza+permesso, coerente con tutti gli altri servizi VaultCore.
- **F-MED-1**: il login per email sconosciuta ritornava subito, mentre una password errata su un account esistente pagava il costo Argon2id — il solo tempo di risposta rivelava quali email fossero registrate (minaccia #4). Corretto facendo eseguire sempre una `Verify` contro un hash fittizio ma di forma corretta, calcolato una sola volta per tutta la vita del processo (mai per singola request, per non moltiplicare il costo Argon2id ad ogni login/refresh/verifica MFA).
- **F-LOW-1**: `POST /api/tenants` non aveva rate limiting né gestiva lo slug/email duplicato, che risultava in un 500 non gestito. Aggiunto controllo proattivo + fallback su `DbUpdateException` (409 pulito) e applicato il rate limiter già esistente per gli endpoint di auth pubblici.
- **F-LOW-2**: `VaultItemService.RestoreAsync/PermanentlyDeleteAsync/AssignTagAsync/RemoveTagAsync` e tutte le mutazioni di `FolderService`/`TagService` non scrivevano voci di audit log. Aggiunta scrittura audit ovunque mancasse (nuovo `AuditAction.PermanentlyDeleted` per distinguere l'eliminazione irreversibile dal soft-delete).
- **F-LOW-3**: l'API non impostava `UseHsts()` in produzione e leggeva `Connection.RemoteIpAddress` direttamente, il che dietro un reverse proxy avrebbe attribuito ogni richiesta a un solo IP (rate limiter e audit log inclusi). Aggiunto `UseHsts()` fuori da Development e middleware `ForwardedHeaders` (attivo solo per proxy esplicitamente elencati in configurazione, `ForwardLimit` a 1 per non fidarsi di una catena arbitraria fornita dal chiamante).
- **F-INFO-1**: il commento su `RefreshToken.ReplacedByTokenId` prometteva che "la catena può essere invalidata al riuso", ma il codice si limitava a rifiutare il token già ruotato senza mai revocare i discendenti. Un token rubato e riusato più tardi avrebbe lasciato valido il token discendente ottenuto dall'attaccante. Corretto: al rilevamento di un riuso, l'intera catena discendente viene revocata (incluso il token attualmente attivo), forzando un nuovo login; l'evento è tracciato con `AuditAction.SessionsRevoked`.
- **F-INFO-2** (chiave di firma JWT di sviluppo in `appsettings.Development.json`): valutato e accettato come non azionabile — è per definizione solo per sviluppo locale.

Tutti i fix sono coperti da test di regressione (vedi `VaultMembershipTests`, `AuthenticationTests`) e l'intera suite (298 test) passa. Prossima revisione completa: da programmare prima del rilascio in produzione o dopo modifiche rilevanti ad autenticazione/tenancy/crittografia.
