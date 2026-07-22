# Import / export

> Stato: export/import cifrato proprietario implementato (vedi sezione Stato in fondo); import CSV da altri password manager resta backlog (v2).

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

Implementato l'export/import cifrato proprietario (backup completo del vault), non l'import CSV da altri password manager: quest'ultimo resta backlog (v2), richiede decisioni su quali formati dare priorità e come mappare colonne non standard.

`Pages/VaultBackup.razor` (`/vault/{vaultId}/backup`): l'export raggruppa tutte le voci, cartelle e tag del vault corrente in un file JSON scaricabile — **nessuna modifica lato server**, dato che `VaultItemResponse.EncryptedPayload` è già ciphertext AES-256-GCM sotto la DEK del vault. Il codice di export/import non decifra né ri-cifra mai nulla, si limita a riassemblare quello che gli endpoint esistenti già restituiscono: il file è quindi reimportabile solo nell'account da cui proviene (un import in un account diverso produce voci non decifrabili, comportamento atteso). L'import ricrea cartelle/tag per nome (riusando quelli esistenti invece di duplicarli) e aggiunge sempre le voci come nuove, senza mai sovrascrivere.

Nuovo `FileDownloadJsInterop`/`wwwroot/js/download.js` (Blob + object URL + click sintetico — Blazor WASM non ha un'API filesystem propria), sullo stesso pattern di `ClipboardJsInterop`. Due nuovi metodi su `VaultApiClient` (`CreateTagAsync`, `AssignTagAsync`) contro endpoint server già esistenti.

Verificato dal vivo in un browser reale: creata una Password e una Nota sicura, esportate, il file scaricato analizzato (versione formato e conteggio voci corretti), reimportato lo stesso file nello stesso vault, confermato che entrambi i titoli compaiono ora due volte (l'import aggiunge, non sovrascrive) e che la voce password reimportata si decifra correttamente (round-trip AES-256-GCM reale attraverso il file scaricato, non mockato). Nessun nuovo test dedicato (lavoro solo `Web.Client`); 385 test invariati e verdi.
