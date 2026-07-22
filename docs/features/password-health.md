# Password health / security dashboard

> Stato: implementata (libreria di analisi + UI Blazor, vedi "Stato" in fondo).

## Scopo

Aiutare l'utente a identificare e correggere password deboli, riutilizzate o compromesse.

## Requisiti funzionali (proposta)

- Dashboard con punteggio complessivo di "salute" del vault.
- Rilevamento password deboli (entropia stimata sotto soglia) — calcolato **client-side** dopo decifratura, mai inviando la password al server per l'analisi.
- Rilevamento password riutilizzate tra più voci — confronto client-side (es. hash locale delle password decifrate, mai trasmesso).
- Controllo "password compromessa" via servizio esterno tipo *Have I Been Pwned* usando il pattern **k-anonymity** (invio solo dei primi 5 caratteri dell'hash SHA-1, mai la password né l'hash completo) — unico caso in cui è ammessa una chiamata di rete legata (indirettamente) a un secret, e va documentato esplicitamente come eccezione controllata alla policy di [../security-model.md](../security-model.md).
- Suggerimento di aggiornamento con generatore integrato (vedi [password-manager.md](password-manager.md)).

## Requisiti di sicurezza

- Qualunque integrazione con servizi esterni per il check breach deve rispettare k-anonymity o protocolli equivalenti a divulgazione zero — mai inviare password o hash completi a terzi.
- L'analisi di forza/riuso resta interamente client-side.

## Stato

Libreria di analisi implementata in `CffVaultManager.Crypto` (nessun tocco lato Api/Infrastructure/Domain, coerente con "resta interamente client-side" sopra):

- `IPasswordStrengthService`/`PasswordStrengthService` — stima l'entropia con la formula classica lunghezza × log2(dimensione del pool di caratteri usato), la stessa baseline semplice usata da molti indicatori di forza. Deliberatamente **non** un estimatore consapevole di pattern (tipo zxcvbn): non riconosce una password ripetuta o una parola di dizionario, che può ottenere un punteggio artificialmente alto sulla sola dimensione del pool.
- `IPasswordReuseService`/`PasswordReuseService` — raggruppa gli ID delle voci che condividono la stessa password decifrata (confronto per uguaglianza esatta, case-sensitive).
- `IBreachCheckService`/`HibpBreachCheckService` — controllo "password compromessa" via l'API k-anonymity di Have I Been Pwned; vedi [../security-model.md](../security-model.md#eccezione-controllata-controllo-password-compromesse-k-anonymity) per l'eccezione esplicita alla policy di rete. Verificato dal vivo contro l'API reale (non solo mockato nei test): la password "password" risulta in ~52 milioni di occorrenze, una stringa casuale in 0.

21 nuovi test (`CffVaultManager.Crypto.Tests`).

## UI Blazor (`Web.Client`)

Nuova pagina `Pages/PasswordHealth.razor` (`/password-health`, `[Authorize]`, link "Salute password" in `MainLayout.razor`) — **decisione di design esplicita** (vedi sotto): nessun round-trip al server, nessuna notifica via email. La dashboard è l'unica forma di "notifica" per password compromesse in questo progetto.

- Elenca tutte le voci di tipo Password in tutti i vault a cui l'utente ha accesso (personali e di organizzazione, stesso elenco di `VaultApiClient.ListVaultsAsync`/`ListItemsAsync`), le decifra client-side (stesso branch `MySharedAccess`/`ItemKeyResolver` già usato da `VaultItems.razor` per le voci promosse a chiave dedicata), poi esegue in sequenza: `IPasswordReuseService.FindReusedGroups`, `IPasswordStrengthService.EstimateStrength`, `IBreachCheckService.CheckPasswordAsync` (una sola chiamata HIBP per valore di password distinto — le password riutilizzate condividono l'esito).
- Riepilogo (analizzate/deboli/riutilizzate/compromesse) + tabella ordinata per rischio decrescente, con link diretto a ogni voce.
- **Nessun dato lascia mai il browser per questa funzionalità, nemmeno per segnalare che una voce è compromessa**: l'unica chiamata di rete è verso l'host HIBP (`api.pwnedpasswords.com`), mai verso l'Api di questo progetto. Registrato in `Program.cs` con un `HttpClient` dedicato (`AddHttpClient<IBreachCheckService, HibpBreachCheckService>()`), separato dal client "Api" con bearer token — nessuna interferenza tra i due.
- Verificato dal vivo in browser (non solo nei test): tre voci Password reali (una password nota e debole/compromessa duplicata su due voci, una forte e unica), la dashboard ha correttamente mostrato 2 riutilizzate e 2 compromesse (~2.27 milioni di occorrenze reali da HIBP) e 0 per la voce forte — confermando sia la decifratura client-side sia la chiamata di rete k-anonymity dal vivo, non mockata.

**Decisione di design**: in fase di scoping è stata valutata anche una notifica email server-mediata (il client segnala al server solo "questa voce è compromessa", mai quale password, con throttling via audit log) — scartata a favore della sola dashboard in-app per non far mai transitare verso il server nemmeno un flag di metadato su quali voci sono compromesse, a costo di richiedere che l'utente apra la pagina per accorgersene (nessun alert proattivo/email in questa fase).
