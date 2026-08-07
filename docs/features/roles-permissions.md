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

## Invito di nuovi utenti in un tenant

Scoperto mancante durante il debug di un problema di condivisione riportato dal titolare: la
condivisione (singola voce o vault di organizzazione) è per design scoped al tenant del chiamante,
ma non esisteva alcun modo funzionante di aggiungere un secondo utente a un tenant esistente.
`POST /api/users` (`UserRegistrationService.RegisterInTenantAsync`) esiste dalla Fase 0 ma non ha
mai avuto una UI, ed è comunque architetturalmente inutilizzabile così com'è: richiede
`AuthHash`/`EncryptedDek`/salt/parametri KDF del **nuovo** utente, derivabili solo client-side dalla
sua master password — un Admin non può produrli per conto di qualcun altro senza violare lo
zero-knowledge. Resta non toccato, semplicemente non più usato da alcun flusso reale.

**Design implementato**: invito a due fasi, entità nuova `UserInvitation`
(`src/CffVaultManager.Domain/Entities/UserInvitation.cs`, mirror esatto di `ExternalShareLink`) —

1. **Invita** (Admin, autenticato): `POST /api/tenant/users/invitations` (`{ Email, Role }`) crea la
   riga (7 giorni di validità) e invia un'email con un link `{App:PublicUrl}/invite/{token}` — nuova
   chiave `App:PublicUrl`, riusa il `PUBLIC_DOMAIN` già esistente in `docker-compose.yml`/`.env`
   (Api e Web condividono lo stesso dominio pubblico, vedi `docs/deployment.md`), nessuna nuova
   variabile d'ambiente. `Token` è alta entropia (256 bit, `RandomNumberGenerator`) e **in chiaro**
   a riposo — stesso trade-off già accettato per `ExternalShareLink.Token` — ma codificato
   URL-safe (`+`/`/` sostituiti, `=` rimosso) invece del base64 standard già usato lì, per evitare
   che un `/` nel token rompa il match della route Blazor `/invite/{Token}`.
2. **Accetta** (pubblico, nessun account ancora esistente): il destinatario apre il link,
   `GetPreviewAsync` mostra tenant/ruolo/invitante prima di committarsi, poi sceglie la propria
   master password — derivazione client-side identica a `Register.razor`
   (`IKeyDerivationService.DeriveKekAsync` → `IAuthHashService.DeriveAuthHash` →
   `IDekService.GenerateDek`/`EncryptDek`) — e `POST /api/tenant/users/invitations/{token}/complete`
   crea `User`+`Vault` "Personale" e consuma l'invito. Nessun auto-login al successo, per coerenza
   con `Register.razor` (redirect a `/login`, non stabilisce sessione).

Deliberatamente **non riusa** `UserRegistrationService.RegisterInTenantAsync` — stesso principio già
seguito per `AccountRecoveryService` rispetto ad `AuthenticationService.VerifyMfaAsync`: duplicazione
minima (creare `User`+`Vault`, ~10 righe) per non rischiare di toccare codice di login sensibile e
testato. Email univoca globalmente (`Users.Email`, indice univoco) verificata sia a `InviteAsync`
(errore pulito, 409) sia a `AcceptAsync` (difesa in profondità contro una race, con l'indice DB come
backstop finale). Isolamento tenant: liste/revoca sempre scoped al tenant del chiamante (query
filter standard su `UserInvitation`); solo la lookup pubblica per token bypassa il filtro
(`IgnoreQueryFilters()`, stesso pattern di `ExternalShareLinkService`). Anti-enumeration: token
sconosciuto/scaduto/revocato rispondono sempre allo stesso 404, mai distinti.

Nuovo `GET /api/tenant/users` (Admin, solo email/ruolo/data creazione) — senza, la pagina
`/users` (`Web.Client/Pages/TenantUsers.razor`, link "Utenti" in navbar solo per Admin) non avrebbe
potuto mostrare i membri già esistenti del tenant, nemmeno quello stesso.

`UserInvitationCleanupHostedService` (24h, mirror esatto di
`TenantProvisioningRequestCleanupHostedService`) purga gli inviti scaduti mai accettati — quelli
accettati vengono rimossi immediatamente da `AcceptAsync`.

17 nuovi test (10 Infrastructure inclusi tenant-scoping/expiry/revoca + 7 Api incluso il
round-trip completo invito→accept→login riuscito con le credenziali appena create; 613 in totale
nella solution).

## UX essenziale

- Sezione "Gestione utenti" visibile solo agli Admin, filtrata al proprio tenant.
- Dashboard SuperAdmin separata dall'applicazione principale (idealmente un'area `/admin` con routing e autorizzazione dedicati), che non espone mai un elenco di vault/secrets, solo metadati di tenant.

## Stato

RBAC (SuperAdmin/Admin/Operator) implementato dalla Fase 0, in uso in tutta l'applicazione. Invito
di nuovi utenti in un tenant esistente implementato (vedi sezione dedicata sopra) — questo era
l'unico pezzo di questo documento rimasto genuinely "da pianificare".
