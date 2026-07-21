# Import / export

> Stato: backlog (v2) — non richiesta per l'MVP.

## Scopo

Permettere la migrazione da/verso altri password manager e il backup dei dati dell'utente.

## Requisiti funzionali (proposta)

- **Import**: supporto formati CSV comuni (Bitwarden, 1Password, LastPass, Chrome) con mapping campi configurabile.
- **Export**: export cifrato (formato proprietario protetto da master password) come opzione predefinita; export CSV in chiaro disponibile solo con warning esplicito e conferma (rischio: file in chiaro su disco).
- Backup completo del vault (tutte le voci, cartelle, tag) in formato cifrato scaricabile dall'utente.

## Requisiti di sicurezza

- L'import processa i dati **client-side**: il file CSV/JSON caricato viene letto e cifrato localmente prima di essere inviato al server, mai salvato in chiaro anche temporaneamente lato server.
- L'export in chiaro deve mostrare un avviso esplicito sui rischi (il file non è protetto) e idealmente suggerire l'export cifrato come default.
- Cancellazione sicura di eventuali file temporanei creati durante import/export.

## Stato

Backlog.
