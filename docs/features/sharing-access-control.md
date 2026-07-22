# Condivisione e controllo accessi

> Stato: **parzialmente promossa a MVP** dal modello multi-tenant — vedi nota sotto. Il caso base "vault di organizzazione condiviso tra i membri di un tenant" è necessario da subito; condivisioni ad-hoc tra singoli utenti restano backlog v2. Fase 4 (condivisione granulare di singola voce) in corso: il link di condivisione esterna (verso chi non ha un account) è implementato — vedi "Link di condivisione esterna" più sotto; la condivisione live tra utenti dello stesso tenant (ruoli owner/editor/viewer) resta da fare.

## Nota — impatto della multi-tenancy

Con l'introduzione dei tenant ([../multi-tenancy.md](../multi-tenancy.md)), il `Vault` con `IsOrganizationVault = true` (vedi [../data-model.md](../data-model.md)) richiede questo meccanismo fin dalla Fase 1: senza crittografia asimmetrica, un vault di organizzazione non potrebbe essere letto da più utenti restando zero-knowledge. Lo scope minimo per l'MVP è quindi:

- **In scope Fase 1**: un Admin può creare un vault di organizzazione e invitare membri del proprio tenant (Operator/Admin) con permesso lettura/modifica, usando lo schema a chiave asimmetrica descritto sotto.
- **Backlog v2**: condivisione granulare di singole voci tra utenti arbitrari, ruoli fini (owner/editor/viewer) oltre a lettura/modifica, condivisione cross-tenant (che comunque non deve mai essere possibile, per definizione di tenant isolation).

## Scopo

Permettere la condivisione controllata di singole voci o interi vault tra più utenti dello stesso tenant, mantenendo il principio zero-knowledge.

## Requisiti funzionali

- Condivisione di un vault (in particolare il vault di organizzazione) o di una singola voce con un altro utente dello **stesso tenant**, con permessi (sola lettura / modifica).
- Revoca della condivisione in qualunque momento.
- Vault "di gruppo" con più proprietari/membri e ruoli (owner, editor, viewer) — ruoli fini in backlog v2, lettura/modifica sufficiente per l'MVP.

## Requisiti di sicurezza (il punto più delicato del progetto)

- La condivisione zero-knowledge richiede crittografia asimmetrica: ogni utente ha una coppia di chiavi pubblica/privata; la DEK (o una DEK dedicata al vault condiviso) viene cifrata con la chiave pubblica del destinatario, cifratura eseguita client-side dal mittente.
- Il server media lo scambio delle chiavi pubbliche ma non ha mai accesso alle chiavi private né alle DEK in chiaro.
- L'invito a un vault di organizzazione è comunque vincolato al tenant: l'endpoint di invito deve verificare che il destinatario appartenga allo stesso `TenantId` del vault (vedi [../multi-tenancy.md](../multi-tenancy.md)) — un Admin non può invitare un utente di un altro tenant.
- La revoca di un accesso condiviso deve invalidare l'accesso futuro (il destinatario perde la possibilità di decifrare nuovi aggiornamenti), ma non può "cancellare" copie già decifrate localmente dal destinatario — limite intrinseco da comunicare chiaramente in UX.

## Stato

Scope minimo (vault di organizzazione, stesso tenant) implementato per Fase 1.

**Schema crittografico** (design validato in un browser reale prima di scrivere codice — vedi [encryption-key-management.md](encryption-key-management.md)): ECIES-style hybrid encryption su X25519 (ECDH) + HKDF-SHA256 + AES-256-GCM, tutto via `BouncyCastle.Cryptography` (`CffVaultManager.Crypto.X25519KeyExchangeService`, mai registrato lato server — solo per il futuro client Blazor). Ogni membro ha una coppia di chiavi X25519 (`User.PublicKey`/`EncryptedPrivateKey`, quest'ultima cifrata con la propria DEK); la DEK del vault di organizzazione non esiste mai in un'unica colonna cifrata, ma solo come N copie indipendenti — una per membro attivo — in `VaultMembership.WrappedVaultDek` (più `EphemeralPublicKey`, la chiave pubblica effimera del mittente usata per quel singolo wrapping).

**Modello dati**: nuova entità `VaultMembership` [tenant-scoped] — `VaultId`, `UserId`, `Permission` (`Read`/`ReadWrite`), `WrappedVaultDek`, `EphemeralPublicKey`, `InvitedByUserId`, `CreatedAt`, `RevokedAt` (nullable — la riga resta per audit anche dopo la revoca). Indice univoco filtrato `(TenantId, VaultId, UserId) WHERE RevokedAt IS NULL`: al più una membership attiva per utente per vault.

**Controllo accessi**: `VaultAccessGuard.GetAccessibleVaultAsync` sostituisce (per `VaultItemService`, `FolderService`, `TagService`) il precedente controllo solo-proprietario — un vault personale resta ownership-only (`ReadWrite` implicito per il proprietario), un vault di organizzazione richiede una membership attiva e restituisce il permesso di quella membership. Le operazioni di scrittura verificano `Permission == ReadWrite` e lanciano `InsufficientVaultPermissionException` (→ `403`) altrimenti; qualunque mancanza di accesso (vault inesistente, membership assente o revocata) è sempre "not found" (`404`), mai "forbidden", per non rivelare l'esistenza del vault a chi non ne fa parte.

**Endpoint**: `POST/GET /api/vaults/organization` (creazione ed elenco vault di organizzazione accessibili), `POST /api/vaults/{vaultId}/memberships` (invito, solo Admin), `POST /api/vaults/{vaultId}/memberships/{userId}/revoke` (revoca, solo Admin), `GET /api/vaults/{vaultId}/memberships` (elenco membri, qualunque membro attivo), `GET /api/tenant/users/{userId}/public-key` (per il client che deve cifrare la DEK per un nuovo invitato — mai cross-tenant).

**Invito**: sincrono, guidato dal client del mittente — nessuno stato "in sospeso/da accettare" (scelta deliberata: l'operazione crittografica non richiede la partecipazione attiva dell'invitato, la chiave pubblica è per definizione condivisibile con chiunque nello stesso tenant).

**Revoca**: ruota davvero la DEK del vault, non si limita a cancellare la riga di membership. Il client invia in un'unica richiesta gli item ri-cifrati con la nuova DEK e i nuovi wrapping per tutti i membri rimanenti; il server verifica che l'insieme di item forniti corrisponda esattamente agli item correnti non eliminati del vault e che l'insieme di membri forniti corrisponda esattamente ai membri attivi rimanenti (escluso il revocato) — un mismatch in entrambi i casi è un `409`. Questo è l'unico modo per soddisfare il requisito "invalidare l'accesso futuro" già scritto in questo documento; una revoca che si limitasse a bloccare le API future lascerebbe il membro revocato in grado di decifrare qualunque item non ancora aggiornato dopo la sua revoca. Limite residuo intrinseco e non risolvibile: copie già decifrate localmente dal revocato restano leggibili da lui — comunicarlo chiaramente in UX.

62 test (12 `CffVaultManager.Crypto.Tests` per lo scambio di chiavi, 32 `CffVaultManager.Infrastructure.Tests`, 18 `CffVaultManager.Api.Tests` end-to-end).

**Fix di sicurezza (Fase 2, F-HIGH-1)**: `InviteAsync`/`RevokeAsync` verificavano solo che il vault appartenesse allo stesso tenant del chiamante, non che il chiamante fosse effettivamente un membro attivo del vault stesso — un Admin dello stesso tenant ma estraneo al vault poteva quindi auto-invitarsi (o revocare membri) su qualunque vault organizzativo del tenant. Corretto riusando `VaultAccessGuard.GetAccessibleVaultAsync` (lo stesso controllo già applicato a `VaultItemService`/`FolderService`/`TagService`) anche qui, così il chiamante deve avere una membership attiva con permesso `ReadWrite` per invitare o revocare. 3 nuovi test di regressione — vedi [../security-model.md#stato-revisione-sicurezza](../security-model.md#stato-revisione-sicurezza).

Da fare: pagine Blazor (`Web.Client`) per creare/gestire vault di organizzazione e membership (la generazione della coppia di chiavi lato client, prerequisito bloccante, è ora implementata — vedi sotto). Ruoli fini oltre Read/ReadWrite per i vault di organizzazione restano backlog v2/Fase 4.

## Generazione della coppia di chiavi X25519 (prerequisito, implementato)

Fino a questo punto nessun client generava mai `User.PublicKey`/`EncryptedPrivateKey`: restavano sempre `null`, rendendo la condivisione (vault di organizzazione o singola voce) inutilizzabile in pratica nonostante lo schema crittografico e gli endpoint esistessero già. Risolto con:

- `POST /api/auth/keypair` (autenticato) — imposta la coppia di chiavi **una sola volta**: un secondo tentativo restituisce `409`, perché rigenerarla orfanizzerebbe qualunque wrap già fatto per la chiave pubblica precedente (nessuna rotazione ancora prevista). `GET /api/auth/me` espone ora anche `HasKeyPair`.
- `Web.Client`: nuovo `KeyPairProvisioningService`, risolto eagerly all'avvio come `TokenRefreshScheduler` — si sottoscrive a `SessionState.Changed` e, al primo sblocco della sessione, controlla `HasKeyPair`; se assente genera la coppia (`IAsymmetricKeyExchangeService.GenerateKeyPair()`, non ancora registrato in `Web.Client` prima d'ora), cifra la chiave privata con la DEK di sessione (stesso schema di qualunque altro secret dell'utente) e la carica. Silenzioso e best-effort: un fallimento transitorio non interrompe l'uso dell'app, viene ritentato al prossimo sblocco.

Verificato dal vivo in un browser reale: dopo il login, `GET /api/auth/me` seguito da `POST /api/auth/keypair` (204) osservati sulla rete reale; chiave pubblica (32 byte) e chiave privata cifrata (61 byte = 1 versione + 12 nonce + 32 chiave + 16 tag, `EncryptedBlob` reale) confermate nel database. 6 nuovi test (3 Infrastructure + 3 Api; 417 in totale nella solution).

## Link di condivisione esterna (Fase 4, implementato)

Permette di condividere una singola voce (v1: solo Password) con chi **non ha un account** su questo tenant — un link a scadenza configurabile verso una pagina pubblica. Meccanismo indipendente dalla condivisione tra utenti dello stesso tenant descritta sopra: non serve alcuna coppia di chiavi X25519, perché il destinatario non ha un'identità con cui fare ECDH.

**Schema crittografico**: il client genera una chiave simmetrica AES-256-GCM monouso (`RandomNumberGenerator`, mai derivata da nient'altro), cifra un piccolo snapshot dei campi essenziali (Titolo, Username, Password, URL — non l'intera voce, niente cronologia password/note), invia al server solo il ciphertext opaco. La chiave non viene mai inviata al server: viaggia esclusivamente nel **frammento dell'URL** (`https://.../share/{token}#key=...`), che per specifica HTTP non è mai incluso in una richiesta di rete — nemmeno nell'header `Referer`. Il server media solo lo scambio del ciphertext tramite un token casuale ad alta entropia (256 bit, mai l'Id del database), generato e verificato lato server.

**Modello dati**: nuova entità `ExternalShareLink` [tenant-scoped] — `VaultItemId`, `CreatedByUserId`, `Token` (univoco), `EncryptedPayload`, `ExpiresAt`, `CreatedAt`, `RevokedAt`. Il filtro tenant EF Core normale si applica a ogni query autenticata (creazione, elenco, revoca lato proprietario); la lettura pubblica bypassa il filtro esplicitamente (`IgnoreQueryFilters()`, stesso pattern già usato da `AuthenticationService.LoginAsync`/`PreloginAsync` per i lookup pre-autenticazione), perché non esiste alcun contesto tenant risolto per un visitatore anonimo — cercato per token globale univoco, mai una lista.

**Scadenza**: configurabile dal client (preset 15 minuti/1 ora/24 ore/7 giorni, default 1 ora), clampata lato server tra 1 minuto e 7 giorni per evitare link indefiniti. Nessun hosted service dedicato alla pulizia: una riga scaduta o revocata viene eliminata al primo tentativo di accesso (self-cleaning), e la risposta è identica (404) per token inesistente/scaduto/revocato — stessa disciplina anti-enumerazione usata ovunque nel progetto.

**Endpoint**: `POST /api/vaults/{vaultId}/items/{itemId}/share-links` (autenticato, richiede `ReadWrite` sul vault), `GET /api/vaults/{vaultId}/items/{itemId}/share-links` (elenco per gestione), `POST .../share-links/{linkId}/revoke`, `GET /api/share-links/{token}` (**pubblico**, senza autenticazione, rate-limitato con la stessa policy degli endpoint auth pubblici contro il brute-force del token).

**Web.Client**: bottone "Condividi esternamente" in `Shared/PasswordFields.razor` (solo voci Password), nuova pagina pubblica `Pages/SharedItemView.razor` (`/share/{token}`, nessun `[Authorize]`) che legge la chiave dal frammento URL tramite un nuovo `UrlFragmentJsInterop`/`wwwroot/js/urlFragment.js`, decifra client-side e mostra i campi in sola lettura con reveal/copia. Avviso esplicito che il link, una volta condiviso, è leggibile da chiunque lo possieda fino alla scadenza, e di non incollarlo in chat che generano anteprime automatiche (residuo noto e accettato: un bot di anteprima che esegue JavaScript potrebbe consumare il link).

Verificato dal vivo in un browser reale: generato un link da un utente autenticato, aperto in un contesto di browser completamente anonimo (nessun cookie/sessione condivisa), confermata la decifratura corretta (round-trip AES-256-GCM reale) e che un token inventato o già revocato risponda in modo uniforme. 22 nuovi test (15 Infrastructure + 7 Api; 411 in totale nella solution).
