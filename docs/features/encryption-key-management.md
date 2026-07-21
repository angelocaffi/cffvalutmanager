# Gestione chiavi e crittografia

## Scopo

Fornire l'implementazione concreta della gerarchia di chiavi definita in [../security-model.md](../security-model.md), isolata in un progetto/libreria dedicata (`CffVaultManager.Crypto`) per facilitare audit e test mirati.

## Requisiti funzionali

- Derivazione KEK da master password tramite Argon2id (parametri: memoria, iterazioni, parallelismo calibrati e documentati qui una volta scelti).
- Generazione DEK casuale per nuovo utente/vault.
- Cifratura/decifratura DEK con KEK (AES-256-GCM o AES-KW).
- Cifratura/decifratura di ogni `VaultItem.EncryptedPayload` con la DEK, nonce univoco per record.
- **Rotazione DEK**: procedura per generare una nuova DEK, ri-cifrare tutti i `VaultItem` di un utente, aggiornare `EncryptedDek`, senza downtime percepito dall'utente (operazione atomica o con stato transazionale).
- **Cambio master password**: ri-derivazione KEK, ri-cifratura della sola DEK (economico, O(1) rispetto al numero di secrets).

## Requisiti di sicurezza

- Uso esclusivo di API crittografiche standard e testate (`System.Security.Cryptography` in .NET, libreria Argon2 validata) — nessuna implementazione custom di primitive crittografiche.
- Nonce/IV generati con `RandomNumberGenerator.Fill` (o equivalente), mai riutilizzati per la stessa chiave.
- Parametri Argon2id scelti bilanciando sicurezza e UX (tempo di derivazione target: ~300-500ms su hardware client medio).
- Chiavi (KEK, DEK in chiaro) devono avere lifetime minimo in memoria; azzerare i buffer dopo l'uso dove il linguaggio lo consente (`Span<byte>`, `CryptographicOperations.ZeroMemory`).

## Test richiesti

- Round-trip cifratura/decifratura per ogni tipo di payload.
- Verifica che chiave/nonce errati causino fallimento esplicito (AES-GCM tag mismatch) e non decifratura silenziosa corrotta.
- Test di non-regressione sui parametri Argon2id (cambiarli richiede una migration esplicita documentata).

## Stato

Da pianificare. Componente fondazionale: va implementato e testato prima di qualunque feature che persista secrets.
