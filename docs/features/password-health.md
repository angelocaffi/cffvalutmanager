# Password health / security dashboard

> Stato: backlog (v2), non richiesta per l'MVP — ma la libreria di analisi client-side è già implementata (vedi "Stato" in fondo); manca la UI Blazor.

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

21 nuovi test (`CffVaultManager.Crypto.Tests`). Manca ancora: le pagine Blazor (`Web.Client`) — dashboard con punteggio complessivo, generatore integrato per il suggerimento di aggiornamento (il generatore stesso esiste già, vedi [password-manager.md](password-manager.md)).
