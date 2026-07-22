# Import / export

> Stato: export/import cifrato proprietario e import CSV (Chrome/Bitwarden/LastPass + mapping manuale) implementati — vedi sezione Stato in fondo.

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

Implementato l'export/import cifrato proprietario (backup completo del vault) e l'import CSV da altri password manager.

`Pages/VaultBackup.razor` (`/vault/{vaultId}/backup`): l'export raggruppa tutte le voci, cartelle e tag del vault corrente in un file JSON scaricabile — **nessuna modifica lato server**, dato che `VaultItemResponse.EncryptedPayload` è già ciphertext AES-256-GCM sotto la DEK del vault. Il codice di export/import non decifra né ri-cifra mai nulla, si limita a riassemblare quello che gli endpoint esistenti già restituiscono: il file è quindi reimportabile solo nell'account da cui proviene (un import in un account diverso produce voci non decifrabili, comportamento atteso). L'import ricrea cartelle/tag per nome (riusando quelli esistenti invece di duplicarli) e aggiunge sempre le voci come nuove, senza mai sovrascrivere.

Nuovo `FileDownloadJsInterop`/`wwwroot/js/download.js` (Blob + object URL + click sintetico — Blazor WASM non ha un'API filesystem propria), sullo stesso pattern di `ClipboardJsInterop`. Due nuovi metodi su `VaultApiClient` (`CreateTagAsync`, `AssignTagAsync`) contro endpoint server già esistenti.

Verificato dal vivo in un browser reale: creata una Password e una Nota sicura, esportate, il file scaricato analizzato (versione formato e conteggio voci corretti), reimportato lo stesso file nello stesso vault, confermato che entrambi i titoli compaiono ora due volte (l'import aggiunge, non sovrascrive) e che la voce password reimportata si decifra correttamente (round-trip AES-256-GCM reale attraverso il file scaricato, non mockato). Nessun nuovo test dedicato (lavoro solo `Web.Client`); 385 test invariati e verdi.

### Import CSV da altri password manager

Scope v1 (deciso esplicitamente): solo voci di tipo Password (username/password/URL/note/cartella) — gli altri tipi (note sicure, carte, identità) presenti in alcuni export non mappano su un unico schema comune e restano fuori scope. Tre formati riconosciuti automaticamente dalle intestazioni del file, scelti perché hanno uno schema colonne stabile e documentato: **Chrome** (`name,url,username,password`), **Bitwarden** (`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp` — solo le righe con `type=login` vengono importate, le altre scartate), **LastPass** (`url,username,password,totp,extra,name,grouping,fav`). 1Password deliberatamente escluso dal rilevamento automatico: il suo export CSV non ha uno schema stabile (varia per categoria) ed è la stessa 1Password a sconsigliarlo. Per qualunque file non riconosciuto (incluso 1Password) l'interfaccia mostra un mapping manuale colonna→campo, con Titolo e Password obbligatori.

Tutto il parsing/mapping avviene **client-side**: nuovo `CsvParser` (`Web.Client/Models/CsvImport.cs`) — un piccolo parser RFC 4180 scritto a mano (nessuna dipendenza CSV esiste nel progetto), gestisce campi tra virgolette con virgole/newline incorporati e `""` come escape. Il file caricato non lascia mai il browser in chiaro: ogni riga viene convertita in un `PasswordFormModel`, serializzata e cifrata con la DEK di sessione (`AeadCipher.Encrypt`, stesso identico percorso di `VaultItemDetail.razor` per una voce Password nuova) prima di essere inviata al server via `POST /api/vaults/{vaultId}/items` — nessuna modifica lato server. Cartelle (Bitwarden `folder`, LastPass `grouping`) vengono create/riusate per nome esatto (nessuna modellazione di percorsi annidati: `Folder` è già piatto in questo progetto). Un eventuale TOTP (`login_totp`/`totp`) viene accodato alle note come riga `TOTP: <valore>`, non essendoci un campo dedicato su `PasswordPayload` e non giustificando una modifica di schema solo per l'import. Le voci vengono sempre aggiunte come nuove, mai sovrascritte — stesso comportamento del backup proprietario.

UI integrata in `VaultBackup.razor` come terza sezione ("Importa da CSV"), con avviso esplicito che il file contiene le password in chiaro e va eliminato dal dispositivo dopo l'import. Verificato dal vivo in un browser reale con crypto reale (non mockata): tutti e tre i formati riconosciuti correttamente e importati (incluso un campo Chrome con virgola e virgolette incorporate, decifrato correttamente dopo l'import), una riga Bitwarden `type=note` correttamente scartata, cartelle create/riusate per entrambi i formati che le supportano, TOTP accodato correttamente alle note, mapping manuale testato con un file dallo schema arbitrario e verificato che l'username/password/URL scelti manualmente producano una voce corretta. Nessun nuovo test automatico dedicato (lavoro solo `Web.Client`, nessun progetto di test esiste per questo layer); 389 test invariati e verdi.
