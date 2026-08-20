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

## Recovery kit

Backlog v2 (vedi [features/authentication.md](features/authentication.md#recovery-kit)): meccanismo **opzionale, opt-in** da `/security` (non obbligatorio in registrazione, per non appesantire un flusso già rivisto — vedi [multi-tenancy.md](multi-tenancy.md#provisioning-di-un-nuovo-tenant)) per recuperare l'accesso al vault senza la master password, senza violare lo zero-knowledge.

### Meccanismo

Una **Recovery Key** casuale a 256 bit (`RandomNumberGenerator`, generata lato client) wrappa direttamente la DEK già sbloccata in sessione (AES-256-GCM, stesso formato `EncryptedBlob` di `EncryptedDek`) → `User.RecoveryEncryptedDek`. La Recovery Key è mostrata **una sola volta** nella UI subito dopo la generazione (da salvare offline: stampa, cassaforte, ecc.) e mai più recuperabile — il server non la vede mai né la deriva, esattamente come la master password.

A differenza della master password, la Recovery Key non passa da Argon2id: è già ad alta entropia (256 bit generati da RNG, non scelti/memorizzati da un umano), quindi non serve rallentarne la derivazione — l'hardening Argon2id esiste per contrastare il brute force di segreti a bassa entropia, non ha alcun beneficio qui e aggiungerebbe solo costo.

### Prova di possesso lato server (gap trovato in fase di design)

A differenza del login, il server non ha per costruzione modo di verificare che chi chiama "completa il recupero" possieda davvero la Recovery Key: senza un controllo dedicato, chiunque conoscesse solo l'email di un account potrebbe sovrascrivere `EncryptedDek`/master password (account takeover o DoS permanente). Fix: esattamente come `AuthHash` prova la conoscenza della master password, il client deriva anche un `RecoveryAuthHash` deterministico dalla Recovery Key (hash con dominio separato, niente Argon2id per lo stesso motivo di cui sopra) e il server lo verifica contro un `User.RecoveryKeyHash` salvato (via lo stesso `IAuthHashHasher` già usato per `MasterPasswordHash` — riuso deliberato dell'astrazione esistente piuttosto che una nuova, anche se il costo Argon2id è tecnicamente superfluo su un input già ad alta entropia: operazione rara, il costo aggiuntivo è trascurabile).

### Flusso di recupero (pubblico, rate-limitato e anti-enumeration come il resto della superficie auth)

1. `POST /api/auth/recovery/start` (email) → ritorna `RecoveryEncryptedDek` (reale, o un blob fittizio ma stabile — stesso trucco del salt fittizio di `/api/auth/prelogin` — se l'email non esiste o non ha un kit configurato). Il ciphertext da solo è inerte: restituirlo a chiunque non rivela nulla.
2. Il client tenta la decifratura locale con la Recovery Key inserita dall'utente. Se fallisce, errore locale, nessun'altra chiamata (nessuna distinzione server-side possibile tra "email sconosciuta" e "chiave sbagliata": la decifratura è interamente client-side).
3. `POST /api/auth/recovery/verify` (email, `RecoveryAuthHash`) → verifica lato server. Se l'utente ha MFA attivo, il recupero **lo richiede comunque** (bypassare la master password non deve bypassare anche il secondo fattore) — ritorna una sfida riusando lo stesso `IJwtTokenService`/pattern a token JWT di breve durata già usato per `CreateMfaChallengeToken`; altrimenti ritorna direttamente un `RecoveryToken` (nuovo scope JWT dedicato, breve durata, non riutilizzabile come access token, stesso principio di isolamento già documentato per `CreateMfaChallengeToken`).
4. Se richiesto, `POST /api/auth/recovery/verify-mfa` (ChallengeToken, Code, Factor) → riusa la verifica dei fattori già esistente (TOTP/WebAuthn/Email OTP); a successo ritorna il `RecoveryToken`.
5. `POST /api/auth/recovery/complete` (RecoveryToken, nuova master password: `NewAuthHash`/`NewEncryptedDek`/`NewMasterPasswordSalt`/nuovi parametri KDF, generati client-side come nel cambio master password) → applica atomicamente i nuovi materiali, **consuma** il kit di recupero (vedi sotto), revoca tutte le sessioni attive (stesso comportamento già esistente per il cambio master password) e genera una notifica di sicurezza (email + in-app, stessi canali di `SecurityNotificationService`). L'utente deve poi rifare login normalmente con la nuova master password — nessun token emesso direttamente da questo endpoint, stessa scelta già fatta per il cambio master password.

### Invalidazione e monouso

- **Monouso**: dopo un recupero riuscito, `RecoveryEncryptedDek`/`RecoveryKeyHash`/`RecoveryKitGeneratedAt` vengono azzerati — l'utente deve generarne uno nuovo se lo desidera. Difesa in profondità: limita il riuso di un segreto fisico/offline dopo che è stato invocato.
- **Rotazione DEK indipendente** (`DekRotationService`, vedi [encryption-key-management.md](encryption-key-management.md)): genera una DEK nuova, quindi un kit di recupero esistente (che wrappa la DEK vecchia) diventerebbe silenziosamente inutile. Il client non può ri-wrapparlo per il recupero perché la Recovery Key, per design, non è mai persistita né recuperabile lato client dopo la prima visualizzazione — quindi la rotazione **invalida** esplicitamente il kit esistente (stessi tre campi azzerati) e genera una notifica dedicata, per non lasciare l'utente convinto di avere un paracadute che in realtà non funziona più.
- **Il cambio master password (`ChangeMasterPasswordService`) NON invalida il kit**: a differenza della rotazione DEK, ri-wrappa la stessa DEK sotto una KEK nuova — la DEK sottostante non cambia, quindi `RecoveryEncryptedDek` (che wrappa la DEK direttamente, non tramite la KEK) resta valido. Invariante non ovvio, va preservato in ogni modifica futura a `ChangeMasterPasswordService`.

### Tradeoff esplicito

Chi entra in possesso della Recovery Key **e** conosce l'email dell'account può decifrare l'intero vault bypassando del tutto la master password (mitigato solo dall'MFA, se attivo). Questo è intrinseco a qualunque meccanismo di recovery key (stesso tradeoff di 1Password Secret Key, Bitwarden Emergency Access): la sicurezza si sposta sul fatto che l'utente la conservi offline, fuori dalla superficie di attacco digitale — coerente con la scelta già fatta per l'accesso fisico al client ("fuori scope primario" nel modello di minaccia sopra). Va comunicato chiaramente nella UI al momento della generazione, non solo qui.

## Sblocco senza password via Passkey (WebAuthn PRF)

Meccanismo **opzionale, opt-in per dispositivo** da `/security` (vedi [features/authentication.md](features/authentication.md#login-passwordless-via-passkey-webauthn-prf)): permette un login "usernameless" su un dispositivo con biometria/passkey, senza digitare la master password. Non sostituisce la master password (resta l'unico modo per stabilire/recuperare la DEK da zero) — è una scorciatoia aggiuntiva e revocabile per singolo dispositivo, analoga nello spirito al Recovery Kit sopra ma con una fonte di chiave diversa.

### Meccanismo

L'estensione **PRF** di WebAuthn (Level 3) permette all'authenticator di produrre, dato un salt scelto dal Relying Party, un output pseudo-casuale a 32 byte **stabile per quella coppia credenziale+salt** (stesso input → stesso output, ad ogni cerimonia). Questo output — mai visto dal server — viene trattato come equivalente della master password:

```
PRF output (dall'authenticator, mai lascia il client)
      │  HMAC-SHA256(prfOutput, "CffVaultManager:PasskeyDekWrap:v1")
      ▼
PRF-KEK                        — derivata, mai persistita, mai inviata al server
      │  cifra (AES-256-GCM, stesso EncryptedBlob di EncryptedDek)
      ▼
DEK (la stessa DEK già in uso) — persistita SOLO cifrata con la PRF-KEK, su WebAuthnCredential.PrfWrappedDek
```

`HMAC-SHA256` è la primitiva scelta deliberatamente, non HKDF: è l'unica funzione di questo tipo già in uso client-side in questo progetto sotto Blazor WASM (`AuthHashService.DeriveAuthHash`), quindi non introduce un nuovo rischio di compatibilità WASM da verificare da zero (vedi la nota su `AesGcmCipherService`/BouncyCastle più sotto per lo stesso genere di vincolo). Il salt PRF stesso non è un segreto (è solo domain separation) e viene fissato una sola volta lato server dentro le opzioni WebAuthn.

### Perché non rompe lo zero-knowledge

Il server, sia in fase di registrazione sia di login, **verifica solo una assertion/attestation WebAuthn standard** (possesso dell'authenticator, nessun materiale crittografico coinvolto) e **restituisce solo ciphertext** (`PrfWrappedDek`) — esattamente lo stesso ruolo che oggi ha `EncryptedDek` rispetto alla master password. Il PRF output non deve **mai** raggiungere il server in nessuna forma: va estratto e tenuto strettamente client-side, separato dal resto della risposta WebAuthn che invece va verificata server-side (vedi [features/authentication.md](features/authentication.md#login-passwordless-via-passkey-webauthn-prf) per il dettaglio implementativo di dove questo taglio avviene nel codice JS).

### Multi-dispositivo e invalidazione

Ogni passkey/dispositivo ha il proprio secret d'authenticator, quindi il proprio PRF output e la propria copia di `WebAuthnCredential.PrfWrappedDek` — rimuovere un dispositivo invalida solo quella copia, mai le altre. La **rotazione della DEK** (`DekRotationService`) invalida (azzera) tutte le copie `PrfWrappedDek` di un utente, stesso trattamento già riservato al Recovery Kit sopra e per lo stesso motivo: il PRF output non è ri-derivabile lato server, quindi non c'è modo di ri-wrappare la nuova DEK senza una cerimonia interattiva reale su ciascun dispositivo — l'utente riattiva il passwordless dal dispositivo quando vuole, dopo una rotazione.

### Supporto browser/authenticator non universale

L'estensione PRF non è disponibile ovunque (buon supporto su Chrome/Android con Google Password Manager al momento della scrittura; supporto variabile altrove). La UI deve degradare in modo pulito al form email/master password quando non disponibile — mai un errore bloccante.

## Estensione browser (Chrome/Edge, Manifest V3) — v1: solo cattura

Design approvato (vedi [features/browser-extension.md](features/browser-extension.md) per scope e
UX): l'estensione osserva un submit di login riuscito su una pagina qualunque e propone di salvare
username/password/dominio come una normale voce `Password`, con conferma esplicita dell'utente —
mai un salvataggio silenzioso, mai autofill (backlog v2 esplicito, superficie di attacco molto più
ampia e non ancora progettata). Due decisioni chiudono i punti aperti lasciati dal documento di
scope.

### Sessione e DEK: mai persistite, login indipendente dall'app web

Un service worker Manifest V3 (il "background" dell'estensione) viene terminato da Chrome dopo
~30 secondi di inattività, azzerando ogni stato in memoria — molto più aggressivo del "solo un vero
reload di pagina" che oggi fa perdere la sessione nell'app web (vedi `SessionState`,
`TokenRefreshScheduler`). Applicare *lo stesso* principio ("mai persistita su disco") invece di
introdurre una persistenza nuova per compensare: l'utente sblocca l'estensione dal popup con
email + master password — stesso flusso a due passi di `Login.razor`
(`/api/auth/prelogin` → deriva `AuthHash` client-side → `/api/auth/login`), nessun endpoint nuovo —
e la DEK/i token vivono solo in variabili di modulo del service worker per la durata dell'episodio
di veglia corrente. Ogni terminazione richiede un nuovo unlock; nessun uso di `chrome.storage` per
token o DEK (sopravviverebbe a un riavvio del service worker, vanificando lo scopo). **v1 non
condivide la sessione con una tab web già sbloccata** — un ponte cross-context tra pagina e
service worker è una superficie di sicurezza a sé, rimandata a un domani con progettazione dedicata,
non necessaria per il capture-only di v1.

### Crittografia: un documento offscreen, non una seconda implementazione

Il service worker/popup girano in puro JavaScript — non possono eseguire
`CffVaultManager.Crypto` (BouncyCastle via .NET/Blazor WASM) direttamente. Invece di scrivere una
seconda implementazione crittografica in JS/WASM (rischio di divergenza silenziosa da quella già
verificata, es. parametri Argon2id o formato `EncryptedBlob` che driftano tra le due codebase),
l'estensione ospita un **documento offscreen** (`chrome.offscreen`, Manifest V3 — una pagina HTML
nascosta con un vero DOM) che carica un host Blazor WASM minimale, riferendo solo
`CffVaultManager.Crypto`. Espone via `[JSInvokable]` le stesse primitive già in uso da `Web.Client`
(derivazione Argon2id, AES-256-GCM su `EncryptedBlob`, unwrap X25519 per un vault di organizzazione)
— una sola implementazione crittografica in tutto il progetto. Il documento offscreen riceve solo
byte opachi/la master password in chiaro per la singola derivazione richiesta, non accumula stato
oltre la chiamata corrente — stesso principio zero-knowledge del resto del progetto.

### Isolamento content script

Il content script che rileva il submit di un form gira nell'"isolated world" standard di Chrome
(heap JavaScript separato da quello della pagina ospite, stesso DOM) — non condivide mai variabili
globali con la pagina. Comunica con il background **solo** tramite `chrome.runtime.sendMessage`
(mai un canale globale condiviso). Nessuna lettura di campi di pagina al di fuori di un submit
esplicito dell'utente — niente listener su `input`/`keydown`, che aprirebbe la porta a un
keylogging involontario.

### CORS e permessi manifest

L'estensione chiama l'Api da un'origine `chrome-extension://<id>` — va aggiunta a
`Cors:AllowedOrigins` (oggi solo `https://{PUBLIC_DOMAIN}`, vedi `Program.cs`/`docker-compose.yml`).
L'id dell'estensione va **pinnato** con una chiave pubblica fissa in `manifest.json` (`"key"`), così
resta stabile tra caricamento non pacchettizzato e pubblicazione — altrimenti cambierebbe a ogni
reinstallazione e romperebbe la configurazione CORS. Permessi: `content_scripts` con
`matches: ["<all_urls>"]` (necessario — non si sa in anticipo su quale sito l'utente farà login) ma
lo script stesso resta deliberatamente minimo (solo il listener di submit sopra); nessun permesso
host più ampio (`tabs`, `webRequest`) richiesto per lo scope v1.

## Logging e osservabilità

- **Divieto assoluto**: loggare password, numeri di carta, CVV, contenuto di secrets o master password, in qualunque forma (anche mascherata parzialmente, salvo ultime 4 cifre carte dove esplicitamente richiesto dalla UX).
- Audit log delle *azioni* (chi ha letto/creato/modificato/eliminato quale voce, quando), mai del *contenuto*. Vedi [features/audit-log.md](features/audit-log.md).
- Log applicativi (errori, performance) devono passare da uno scrubber che rifiuta payload con pattern noti di secrets prima della scrittura.

## Gestione carte di credito — considerazioni aggiuntive

- Se in futuro si integrano pagamenti reali, valutare la conformità **PCI-DSS**; per un vault "personal", i dati carta sono trattati come qualunque altro secret cifrato, mai trasmessi a processori di pagamento.
- Il PAN (numero carta) va sempre mascherato in UI di default (mostra ultime 4 cifre), con "reveal" esplicito che richiede ri-autenticazione o conferma.
- **Decisione: nessun alert server-side di scadenza carta** (vedi [features/notifications.md](features/notifications.md), [features/credit-cards.md](features/credit-cards.md)). La data di scadenza vive solo dentro `EncryptedPayload`; per notificare "la tua carta sta per scadere" il server dovrebbe conoscere quella data in chiaro (o un campo separato non cifrato con la stessa informazione), il che equivale a fargli vedere una parte del secret — in contrasto diretto con il principio di zero-knowledge (vedi CLAUDE.md, principio 1). Non esiste un meccanismo lato client praticabile che eviti questo senza introdurre un canale non cifrato ad hoc, quindi la feature è stata scartata, non solo rimandata.

## Eccezione controllata: controllo password compromesse (k-anonymity)

Il password health check (vedi [features/password-health.md](features/password-health.md)) introduce l'unica chiamata di rete di questo progetto indirettamente legata a un secret: `IBreachCheckService`/`HibpBreachCheckService` (in `CffVaultManager.Crypto`, eseguito solo client-side) invia ai server di *Have I Been Pwned* i primi 5 caratteri esadecimali dell'hash SHA-1 della password — mai la password né l'hash completo, seguendo il protocollo k-anonymity dell'API stessa. SHA-1 qui non è una scelta di sicurezza di questo progetto (che usa Argon2id/AES-256-GCM ovunque il rischio sia reale): è l'hash su cui è indicizzato il corpus HIBP, mandato dal loro protocollo. Il prefisso a 5 caratteri non è invertibile alla password originale (spazio di ricerca ancora enorme).

## Canale email (SMTP)

`SmtpEmailSender` (vedi [features/notifications.md](features/notifications.md)) è l'unico altro punto in cui dati lasciano il server verso un servizio esterno (il relay SMTP configurato — un provider transazionale o un server dell'utente). Ciò che transita: indirizzo email del destinatario, oggetto e corpo del messaggio — che contengono **solo** un codice OTP a bassa entropia e vita breve (verifica email, MFA Email OTP) o una descrizione testuale di un evento di sicurezza (nuovo login, cambio master password, fattore MFA disattivato). Non transita mai: master password, DEK, contenuto di un `VaultItem` o qualunque altro secret cifrato. Il corpo non viene mai loggato lato server (stessa disciplina già in vigore per non esporre i codici OTP nei log applicativi). Nessun altro servizio esterno riceve mai dati derivati da un secret in questo progetto.

## Dati di fatturazione (provisioning tenant)

`TenantBillingProfile` (vedi [data-model.md](data-model.md#tenantbillingprofile-tenant-scoped-11-con-tenant), raccolto nel flusso di provisioning gated in [multi-tenancy.md](multi-tenancy.md#provisioning-di-un-nuovo-tenant)) persiste in chiaro dati anagrafici/fiscali dell'organizzazione (ragione sociale, indirizzo, Partita IVA/Codice Fiscale, Codice Destinatario SDI/PEC). Questo **non è un'eccezione al principio zero-knowledge**: questi dati non sono mai stati un secret applicativo, sono metadati di business nella stessa classe di fiducia di `Tenant.Name`/`Slug`/`PlanName`, già oggi in chiaro e già oggi visibili a un SuperAdmin per operazioni amministrative (vedi [multi-tenancy.md](multi-tenancy.md#ruoli--riepilogo), "solo metadati amministrativi"). Non vanno mai confusi con — né usati per derivare — materiale crittografico: `TenantProvisioningRequest` porta entrambe le categorie di dati nella stessa riga pending solo perché nascono nella stessa sottomissione, ma restano concettualmente separate (una promossa a `TenantBillingProfile`, l'altra a `User.EncryptedDek`/`MasterPasswordSalt`). Un eventuale addebito reale (fuori scope finché non si sceglie un processore) non deve mai transitare né essere derivato da questi campi da solo — richiederà comunque un consenso esplicito e un metodo di pagamento a parte.

## Integrazione pagamento (PayPal)

Design completo in [features/billing.md](features/billing.md). Punti rilevanti per il modello di minaccia:

- **L'importo addebitato è sempre deciso lato server** (configurazione, mai un valore accettato nel body di `POST /api/billing/checkout`) — altrimenti un client malevolo potrebbe creare un ordine PayPal per un importo arbitrariamente basso e ottenere comunque l'estensione piano.
- **`PayPal:ClientSecret` non lascia mai il server**: solo `PayPal:ClientId` (pubblico per design, richiesto dall'SDK JS di PayPal) raggiunge `Web.Client`. Stessa disciplina già in vigore per `Jwt:SigningKey`/credenziali SMTP — mai in un file committato, solo user-secrets/variabili d'ambiente.
- **Nessuna eccezione zero-knowledge**: importo, valuta, PayPalOrderId e stato del pagamento non sono mai stati un secret applicativo — stessa classe di fiducia di `TenantBillingProfile` (vedi sopra), non richiedono nuova crittografia né bypassano alcun query filter.
- **Enforcement sola-lettura fail-open deliberato sul singolo access token**: il claim `tenant_read_only` viene deciso al login/refresh, non per singola richiesta — un pagamento catturato durante la vita di un token già emesso (pochi minuti) non lo sblocca istantaneamente. Accettato per lo stesso motivo già documentato per la sospensione tenant e la revoca sessioni: nessuna blocklist server-side per JWT stateless già emessi; il client forza un refresh subito dopo una cattura riuscita per non far percepire il ritardo.

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
