# Ruoli e permessi (RBAC multi-tenant)

## Scopo

Definire chi può fare cosa, mantenendo la separazione netta tra "capacità amministrativa" e "accesso ai secrets in chiaro" — vedi il principio in [../multi-tenancy.md](../multi-tenancy.md#admin-e-vault-personali).

## Ruoli

### SuperAdmin

- Scope: piattaforma, cross-tenant.
- Può: creare/sospendere/eliminare tenant, vedere metriche aggregate (numero utenti, storage, stato abbonamento), assistere il supporto clienti su base metadati.
- Non può: decifrare, visualizzare o esportare secrets di alcun tenant; impersonare un utente per accedere al suo vault senza un flusso di consenso esplicito (se mai implementato).
- Creazione: seed iniziale via migration/script di provisioning, non tramite self-registration pubblica.

### Admin (di tenant)

- Scope: singolo tenant.
- Può: invitare/disabilitare utenti del proprio tenant, assegnare ruolo Operator/Admin ad altri utenti, impostare policy di tenant (MFA obbligatoria, durata sessione/auto-lock, retention audit log), consultare l'audit log del proprio tenant.
- Non può: leggere il contenuto dei vault personali degli utenti senza essere stato esplicitamente incluso in una condivisione cifrata (vedi [sharing-access-control.md](sharing-access-control.md)); accedere a dati di altri tenant.

### Operator

- Scope: singolo tenant, proprio profilo.
- Può: gestire il proprio vault personale, partecipare a vault di organizzazione condivisi a cui è stato invitato, secondo il permesso assegnato (lettura/modifica).
- Non può: gestire altri utenti, modificare policy di tenant, vedere l'audit log altrui.

## Matrice permessi (riepilogo)

| Azione | SuperAdmin | Admin (tenant) | Operator |
|---|---|---|---|
| Creare/sospendere tenant | Sì | No | No |
| Invitare/disabilitare utenti nel proprio tenant | No (fuori scope) | Sì | No |
| Impostare policy di tenant (MFA, auto-lock) | No | Sì | No |
| Consultare audit log del proprio tenant | No (solo audit di piattaforma) | Sì | No (solo proprie azioni, se esposto) |
| Leggere/scrivere il proprio vault personale | Se ne ha uno | Sì | Sì |
| Leggere secrets di un altro utente | Mai | Mai (salvo condivisione esplicita) | Mai (salvo condivisione esplicita) |
| Accedere a vault di organizzazione | No | Se invitato | Se invitato |

## Requisiti di sicurezza

- L'autorizzazione (`[Authorize(Roles = ...)]` o policy-based) va sempre combinata con il filtro `TenantId` — un Admin del tenant A non deve poter agire su risorse anche solo passando `TenantId` del tenant B per errore o manipolazione.
- Il cambio di ruolo di un utente è un'azione sensibile: va tracciata in audit log e, idealmente, richiede conferma via MFA di chi la esegue.
- Nessun ruolo deve poter auto-assegnarsi SuperAdmin: la creazione di SuperAdmin avviene fuori dal normale flusso applicativo (script/migration controllata, non endpoint API pubblico).

## UX essenziale

- Sezione "Gestione utenti" visibile solo agli Admin, filtrata al proprio tenant.
- Dashboard SuperAdmin separata dall'applicazione principale (idealmente un'area `/admin` con routing e autorizzazione dedicati), che non espone mai un elenco di vault/secrets, solo metadati di tenant.

## Stato

Da pianificare — fondazionale insieme a [../multi-tenancy.md](../multi-tenancy.md), va implementato in Fase 0/1.
