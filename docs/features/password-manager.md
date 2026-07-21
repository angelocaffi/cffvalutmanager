# Gestione password

## Scopo

Funzionalità core di un password manager: memorizzazione sicura e generazione di credenziali per siti/servizi.

## Requisiti funzionali

- CRUD voce password: Titolo, Username/Email, Password **[cifrato]**, URL, Note **[cifrato]**.
- **Generatore di password**: lunghezza configurabile, set di caratteri (maiuscole/minuscole/numeri/simboli), esclusione caratteri ambigui, opzione passphrase (parole).
- **Cronologia password**: mantenere le versioni precedenti di una password quando viene aggiornata, per riferimento (utile se un servizio esterno non ha ancora recepito il cambio).
- Associazione a più URL per la stessa voce (es. login/sso su più domini dello stesso servizio).
- Indicatore forza password (calcolato client-side, mai inviato al server in chiaro).

## Requisiti di sicurezza

- La password non è mai visibile di default nella lista; richiede azione esplicita ("mostra"/copia).
- Il generatore usa un RNG crittograficamente sicuro, mai `Random` standard.
- La cronologia password è cifrata con la stessa DEK della voce corrente.

## UX essenziale

- Pulsante "genera password" integrato nel form di creazione/modifica.
- Copia rapida username/password con feedback visivo e auto-clear appunti.
- Eventuale badge "password debole" o "riutilizzata" — collegato a [password-health.md](password-health.md) (v2).

## Stato

- CRUD lato server: già coperto genericamente dagli endpoint `vault-core` (`VaultItem` con `Type = Password`); nessun modello dati dedicato, il payload tipizzato (Titolo, Username, Password, URL, Note, PasswordHistory) vive interamente dentro `EncryptedPayload` lato client, come da [data-model.md](../data-model.md).
- Generatore: implementato in `CffVaultManager.Crypto.PasswordGeneratorService` — `GeneratePassword` (lunghezza configurabile, set maiuscole/minuscole/numeri/simboli attivabili singolarmente, esclusione caratteri ambigui `0O1lI`, garanzia di almeno un carattere per categoria selezionata via rejection sampling non posizionale) e `GeneratePassphrase` (n parole da una wordlist di ~2000 termini incorporata come embedded resource, separatore configurabile, capitalizzazione opzionale, numero finale opzionale). RNG sempre `RandomNumberGenerator`, mai `Random`. 56 test unitari.
- Pagine Blazor (`Web.Client`): `VaultItems.razor` (lista, filtro tipo/testo dopo decifratura, preferiti, cestino), `VaultItemDetail.razor` (creazione/modifica, cifratura/decifratura del payload lato client con `IAeadCipherService` e la DEK di sessione) e `Shared/PasswordFields.razor` (campi, generatore integrato con rigenera/usa, indicatore di forza via `IPasswordStrengthService`, password mascherata con reveal esplicito + copia con auto-clear appunti, entrambi tracciati come evento `Revealed`). La cronologia password viene aggiornata automaticamente nel payload cifrato quando la password cambia in fase di modifica. Verificato dal vivo in un browser reale con un vero round-trip di cifratura/decifratura (non solo compilato).
