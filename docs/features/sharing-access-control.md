# Condivisione e controllo accessi

> Stato: **parzialmente promossa a MVP** dal modello multi-tenant — vedi nota sotto. Il caso base "vault di organizzazione condiviso tra i membri di un tenant" è necessario da subito; condivisioni ad-hoc tra singoli utenti restano backlog v2.

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

Da fare: pagine Blazor (`Web.Client`) per creare/gestire vault di organizzazione e membership, generazione della coppia di chiavi lato client (al momento non esiste alcun client che la generi — `User.PublicKey`/`EncryptedPrivateKey` restano `null` finché non viene costruito). Estensioni (condivisione di singole voci, ruoli fini oltre Read/ReadWrite) restano backlog v2/Fase 4.
