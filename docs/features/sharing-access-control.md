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

Scope minimo (vault di organizzazione, stesso tenant) necessario in Fase 1 — richiede design crittografico dedicato prima dell'implementazione, da validare insieme a [encryption-key-management.md](encryption-key-management.md) prima di iniziare. Estensioni (condivisione singola voce, ruoli fini) restano backlog v2.
