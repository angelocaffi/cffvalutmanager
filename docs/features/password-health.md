# Password health / security dashboard

> Stato: backlog (v2) — non richiesta per l'MVP.

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

Backlog — da riprendere dopo il completamento delle feature core.
