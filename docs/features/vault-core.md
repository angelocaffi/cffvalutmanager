# Vault core (organizzazione)

## Scopo

Funzionalità trasversali di organizzazione e navigazione del vault, comuni a tutti i tipi di voce (password, carte, secrets generici).

## Requisiti funzionali

- **Cartelle**: struttura piatta o gerarchica (da decidere — piatta consigliata per v1, più semplice da implementare e da usare).
- **Tag**: multipli per voce, per organizzazione trasversale alle cartelle.
- **Preferiti**: marcare voci per accesso rapido.
- **Ricerca**: per titolo, username, URL, tag — **client-side dopo decifratura** (vedi nota in [../data-model.md](../data-model.md) sulla ricerca su dati cifrati).
- **Ordinamento e filtri**: per tipo, cartella, data modifica, ultimo accesso.
- **Cestino / soft delete**: le voci eliminate restano recuperabili per un periodo (es. 30 giorni) prima della cancellazione definitiva.

## Secrets generici

Oltre a password e carte (che hanno documenti dedicati), il vault supporta voci generiche per:

- Note sicure (testo libero cifrato).
- API key / token.
- Chiavi SSH / certificati.
- Campi custom key-value definiti dall'utente (es. "PIN badge ufficio: 1234").

Ogni tipo generico usa lo stesso meccanismo di cifratura del payload descritto in [encryption-key-management.md](encryption-key-management.md).

## Requisiti di sicurezza

- Le operazioni di cartella/tag (metadati non sensibili) possono essere gestite lato server senza decifratura; il contenuto delle voci resta sempre cifrato end-to-end.
- Il "cestino" mantiene i dati cifrati con la stessa DEK: la cancellazione definitiva deve essere una vera eliminazione fisica dal database, non solo un flag.

## UX essenziale

- Vista lista con icone per tipo (password/carta/nota/generico).
- Dettaglio voce con campi mascherati di default e pulsante "mostra" (richiede eventualmente conferma per campi ultra-sensibili come CVV).
- Copia negli appunti con auto-clear dopo N secondi (per password, CVV, numeri carta).

## Stato

Implementato per i vault personali: `POST/GET /api/vaults`, `.../folders`, `.../tags`, `.../items` (con `/trash`, `/{itemId}/restore`, `/{itemId}/permanent`, `/{itemId}/tags/{tagId}`). L'accesso è vincolato a `OwnerUserId`: nessun ruolo di tenant (incluso Admin) può leggere il vault personale di un altro utente. I vault di organizzazione restano fuori scope (verranno affrontati in Fase 1 insieme al modello di condivisione).

### Secrets generici

Implementati entrambi i tipi generici come ultimo tassello di `VaultItemType`, riusando `VaultItem` senza alcuna modifica lato server (Api/Infrastructure/Domain), a conferma del design generico dell'entità: **Nota sicura** (titolo + contenuto testuale libero, `SecureNotePayload`) e **Secret generico** (titolo + lista dinamica di campi chiave/valore + note, `GenericSecretPayload`/`GenericSecretField` — per API key, chiavi SSH, PIN o qualunque dato non previsto dagli altri tipi). Pagine Blazor: `Shared/SecureNoteFields.razor` (titolo + textarea) e `Shared/GenericSecretFields.razor` (titolo + righe chiave/valore aggiungibili/rimovibili + note), integrate in `VaultItems.razor` (voce nel menu "Nuova voce", filtro per tipo, badge/sottotitolo in lista), `VaultTrash.razor` e `VaultItemDetail.razor` (create/modifica/decifratura). Nessun reveal-gating: a differenza di password/CVV/chiave privata, questi campi non sono considerati ultra-sensibili da mascherare di default. Verificato dal vivo in un browser reale: creazione di una nota multi-riga e di un secret generico con due campi custom, round-trip di cifratura/decifratura reale (AES-256-GCM) confermato riaprendo la voce. Nessun nuovo test dedicato (lavoro solo `Web.Client`, non coperto dalla suite .NET); build e suite esistente (379 test) invariati e verdi.
