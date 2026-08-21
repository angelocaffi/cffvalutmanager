# Estensione browser

> Stato: design di sicurezza approvato per lo scope v1 (2026-08-20) — vedi
> [security-model.md](../security-model.md#estensione-browser-chromeedge-manifest-v3--v1-solo-cattura).
> In implementazione. Nessuna decisione presa su v2 (autofill).

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

## Requisiti di sicurezza — decisi (vedi [security-model.md](../security-model.md#estensione-browser-chromeedge-manifest-v3--v1-solo-cattura) per il dettaglio completo)

- **Autenticazione**: login indipendente nel popup (stesso flusso a due passi di `Login.razor`), nessuna condivisione di sessione con una tab web già loggata in v1 (backlog v2 esplicito).
- **DEK in memoria nell'estensione**: mai persistita — vive solo per la durata dell'episodio di veglia del service worker, si azzera a ogni sua terminazione (~30s di inattività). Nessun meccanismo di persistenza dedicato introdotto.
- **Crittografia**: nessuna seconda implementazione JS/WASM — un documento offscreen (`chrome.offscreen`) ospita un host Blazor WASM minimale che riferisce `CffVaultManager.Crypto` direttamente, esposto al service worker via `[JSInvokable]`.
- **Isolamento del content script**: isolated world standard di Chrome, comunicazione solo via `chrome.runtime.sendMessage`, nessun listener su `input`/`keydown` — solo submit esplicito.
- **CORS lato Api**: `chrome-extension://<id-pinnato>` aggiunto a `Cors:AllowedOrigins`; id pinnato con una chiave pubblica fissa in `manifest.json` per restare stabile tra caricamento non pacchettizzato e pubblicazione.
- **Permessi manifest**: `content_scripts` su `<all_urls>` (necessario, sito di login non prevedibile) ma script stesso ridotto al minimo; nessun permesso host più ampio richiesto per v1.

## UX essenziale (proposta)

Popup minimale (icona nella toolbar del browser): stato sessione in alto, prompt di salvataggio come piccola card che appare in-page dopo un submit rilevato (non il popup stesso, per non richiedere all'utente di aprirlo attivamente ogni volta).

## Stato

- **Fase 1/2 (fatto)**: design di sicurezza approvato e documentato, host crypto offscreen
  (`src/CffVaultManager.Extension.CryptoHost`) — Blazor WASM minimale senza UI che riferisce
  `CffVaultManager.Crypto` direttamente.
- **Fase 3 (fatto)**: scheletro estensione in `browser-extension/` — `manifest.json` (Manifest V3,
  `key` pinnata → id estensione `ggflohkjkhokbbknoallojkhkhllbljd`, stabile tra caricamento non
  pacchettizzato ed eventuale pubblicazione), `background.js` (ciclo di vita del documento
  offscreen via `chrome.offscreen`), `offscreen/offscreen.html` + `offscreen-bridge.js` (bridge
  JS↔`[JSInvokable]`), popup di test usa e getta. Verificato dal vivo in Chrome: round-trip reale
  Encrypt/Decrypt attraverso `CryptoInterop`, non solo un ping JS.
  - `browser-extension/build.ps1` pubblica `CffVaultManager.Extension.CryptoHost` e copia
    `_framework/` dentro `offscreen/` (non committato, generato — vedi `.gitignore`); da eseguire
    prima di caricare l'estensione e ogni volta che `CffVaultManager.Crypto` cambia.
  - Nota manifest V3: `content_security_policy.extension_pages` deve includere esplicitamente
    `'wasm-unsafe-eval'` (non è nel CSP di default delle pagine estensione) — senza, il boot di
    Blazor WASM nel documento offscreen si blocca silenziosamente. Scoperto e corretto durante la
    verifica dal vivo di questa fase.
  - La chiave privata usata per generare la `key` pinnata non è stata conservata (non serve né per
    il caricamento non pacchettizzato né per la pubblicazione sul Chrome Web Store, che può
    comunque forzare lo stesso id se necessario tramite lo stesso meccanismo).
- **Prossimo (fase 4)**: popup login reale (email/master password → prelogin/login contro l'Api di
  sviluppo → DEK sbloccata in memoria del service worker), al posto del popup di test attuale.
- Nessuna decisione presa su v2 (autofill).
