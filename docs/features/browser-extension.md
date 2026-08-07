# Estensione browser

> Stato: backlog, non ancora pianificata in dettaglio (nessun design di sicurezza approvato, nessun codice).

## Scopo

Permettere di salvare una nuova voce nel vault direttamente mentre si naviga — tipicamente dopo aver compilato un form di login/registrazione su un sito qualunque — senza dover copiare manualmente username/password nell'app web. Target: Chrome ed Edge (stesso motore, stessa API `chrome.*`/Manifest V3, un solo pacchetto); Safari valutato come estensione separata solo dopo che v1 è stabile su Chromium (toolchain completamente diverso — Safari Web Extension richiede conversione/packaging via Xcode e notarizzazione macOS, non un semplice porting del manifest).

## Scope v1 (proposta): solo cattura, non autofill

Deliberatamente ridotto rispetto a un password manager con estensione completa:

- **Dentro scope v1**: l'estensione osserva un submit di form di login riuscito (o un click su un pulsante di submit) su una pagina, propone "Salva in CffVault" con username/password/dominio pre-compilati, l'utente conferma (o modifica/annulla) e la voce viene creata nel vault scelto — stesso schema `Password` già esistente (`VaultItemTypes.Password`), nessuna modifica al modello dati lato server.
- **Fuori scope v1 (backlog v2 esplicito)**: autofill (compilazione automatica di form da parte dell'estensione) e qualunque "content script" che legge campi di pagine per suggerire credenziali esistenti. L'autofill è una superficie di attacco enormemente più grande (matching dominio↔voce, injection in pagine arbitrarie, rischio phishing se il matching è troppo permissivo) e richiede un design di sicurezza dedicato che non è stato ancora fatto — non va introdotto insieme alla v1 solo perché "è la stessa estensione".

## Requisiti funzionali (proposta)

- Popup dell'estensione: stato sbloccato/bloccato del vault (stessa logica di sessione dell'app web — vedi sotto), lista vault disponibili se più di uno, pulsante "Sblocca" che riusa lo stesso flusso di login/master password.
- Rilevamento compilazione form via content script isolato per-tab, nessuna lettura di campi al di fuori di un submit esplicito dell'utente.
- Conferma esplicita prima di ogni scrittura nel vault (mai un salvataggio silenzioso) — coerente con l'assenza generale di automatismi impliciti nel resto del progetto.
- Badge/icona con stato (bloccato/sbloccato) coerente con l'auto-lock già presente nell'app web (`Session.Lock`).

## Requisiti di sicurezza (da approfondire prima di qualunque codice — CLAUDE.md principio 5)

Punti aperti che vanno risolti in `security-model.md` (nuova sezione dedicata) **prima** di iniziare l'implementazione, non durante:

- **Autenticazione**: l'estensione è un nuovo client verso la stessa Api (`/api/auth/*`) — nessun endpoint nuovo previsto per l'auth in sé, ma va deciso dove/come vive il refresh token nel contesto di un'estensione (storage dell'estensione vs `background service worker` in memoria) e se condividere la sessione con una scheda dell'app web già loggata o richiedere un login indipendente.
- **DEK in memoria nell'estensione**: stesso principio zero-knowledge del resto del progetto (la DEK sblocca solo client-side, mai persistita) — ma il "client-side" qui è un service worker di estensione con un ciclo di vita diverso da una tab (può essere terminato e riavviato da Chrome in qualunque momento). Va deciso se questo equivale a un lock automatico immediato (nessuna DEK sopravvive a un riavvio del service worker, quindi nessun problema nuovo) o se serve un meccanismo di persistenza dedicato — la seconda opzione, se mai scelta, avrebbe implicazioni di sicurezza serie e andrebbe motivata esplicitamente.
- **Isolamento del content script**: un content script gira nel contesto della pagina visitata — va garantito che non possa mai leggere/esfiltrare la DEK o il token di sessione dal contesto del background/popup dell'estensione (comunicazione solo tramite i canali sandboxed standard di Chrome, `chrome.runtime.sendMessage`, mai variabili globali condivise).
- **CORS/CSP lato Api**: l'estensione chiamerà l'Api da un'origine `chrome-extension://<id>` — va verificato se serve un'eccezione CORS dedicata (l'Api oggi assume client same-origin/dominio noto, vedi `docs/deployment.md`) e se questo introduce un vettore nuovo da considerare nella checklist di sicurezza.
- **Permessi manifest**: Manifest V3 richiede dichiarare esplicitamente su quali siti il content script gira — va deciso se `<all_urls>` (semplice ma permesso ampio, revisione Chrome Web Store più severa) o un meccanismo di attivazione più mirato.

Nessuna di queste decisioni è presa: vanno risolte in un piano dedicato (stesso processo già seguito per WebAuthn PRF passwordless, vedi [authentication.md](authentication.md)) prima di scrivere codice.

## UX essenziale (proposta)

Popup minimale (icona nella toolbar del browser): stato sessione in alto, prompt di salvataggio come piccola card che appare in-page dopo un submit rilevato (non il popup stesso, per non richiedere all'utente di aprirlo attivamente ogni volta).

## Stato

Non pianificata in dettaglio. Nessun design di sicurezza approvato, nessun codice, nessuna decisione presa sui punti aperti sopra. Da riprendere con un piano dedicato quando si decide di avviarla.
