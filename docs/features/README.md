# Indice feature

Ogni feature ha un documento dedicato con: scopo, requisiti funzionali, requisiti di sicurezza specifici, UX essenziale e stato.

## Fondazionali (Fase 0 — prerequisito)

| Feature | Descrizione | Stato |
|---|---|---|
| [Multi-tenancy](../multi-tenancy.md) | Isolamento organizzazioni, risoluzione tenant, scalabilità | Da pianificare |
| [Ruoli e permessi](roles-permissions.md) | SuperAdmin / Admin / Operator, RBAC + tenant isolation | Da pianificare |

## Core (v1 — MVP)

| Feature | Descrizione | Stato |
|---|---|---|
| [Autenticazione e master password](authentication.md) | Login, master password, sblocco vault, MFA | Da pianificare |
| [Gestione chiavi e crittografia](encryption-key-management.md) | Derivazione chiave, DEK/KEK, rotazione | Da pianificare |
| [Vault core](vault-core.md) | Creazione/organizzazione voci: cartelle, tag, preferiti, ricerca | Da pianificare |
| [Gestione password](password-manager.md) | CRUD credenziali, generatore password, cronologia | Da pianificare |
| [Gestione carte di credito](credit-cards.md) | CRUD carte, mascheramento PAN, scadenze | Da pianificare |
| [Secrets generici](vault-core.md#secrets-generici) | Note sicure, API key, campi custom | Da pianificare |
| [Gestione crypto wallet](crypto-wallets.md) | CRUD wallet, indirizzi/seed phrase, riconoscimento rete | Parziale (validazione client-side) |
| [Audit log](audit-log.md) | Tracciamento azioni su vault e login | Da pianificare |
| [Condivisione e controllo accessi](sharing-access-control.md) | Vault di organizzazione condivisi nello stesso tenant (scope minimo) | Da pianificare |

## V2 e oltre

| Feature | Descrizione | Stato |
|---|---|---|
| [Password health / security dashboard](password-health.md) | Password deboli, riutilizzate, compromesse | Implementata |
| [Abbonamento e pagamento](billing.md) | Trial 30gg, pagamento singolo annuale via PayPal, enforcement sola-lettura | Da pianificare |
| [Import / export](import-export.md) | Migrazione da altri password manager, backup cifrato | Backlog |
| [Condivisione e controllo accessi](sharing-access-control.md) | Condivisione singola voce, ruoli fini (owner/editor/viewer) | Backlog |
| [Notifiche](notifications.md) | Alert di sicurezza (email), promemoria password compromesse | Backlog |

## Come aggiungere una nuova feature

1. Crea `docs/features/<nome-feature>.md` seguendo la struttura degli altri documenti.
2. Aggiungi una riga nella tabella sopra.
3. Se la feature tocca secrets/crittografia, applica la checklist in [../security-model.md](../security-model.md#checklist-di-revisione-sicurezza-da-applicare-a-ogni-feature-che-tocca-secrets).
