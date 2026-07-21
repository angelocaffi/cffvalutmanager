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

- Uso esclusivo di API crittografiche standard e testate — nessuna implementazione custom di primitive crittografiche. Non necessariamente `System.Security.Cryptography`: dove il BCL non funziona sotto Blazor WASM (vedi nota sotto), si usa una libreria managed validata e ampiamente adottata (es. `BouncyCastle.Cryptography`) invece di reimplementare l'algoritmo.
- **Nota — `System.Security.Cryptography.AesGcm` non funziona in Blazor WASM**: verificato live in browser che lancia `PlatformNotSupportedException` sotto il runtime `browser-wasm` (nessun provider crittografico nativo del sistema operativo disponibile lì). `AesGcmCipherService` usa quindi `BouncyCastle.Cryptography` (`GcmBlockCipher`, managed puro, nessuna dipendenza nativa) — stesso identico comportamento su .NET desktop/server e su WASM, stessa interfaccia `IAeadCipherService` e formato `EncryptedBlob`, nessun impatto sui chiamanti. Stessa categoria di scelta già fatta per Argon2id (`Konscious.Security.Cryptography.Argon2`, `DegreeOfParallelism = 1` forzato per compatibilità WASM) — qualunque primitiva usata lato client deve essere verificata in un browser reale prima di considerarla WASM-compatibile, non solo compilata/testata sul runtime .NET server-side (questo bug in `AesGcmCipherService` è rimasto invisibile per diverse iterazioni proprio perché i 122 test del progetto Crypto girano sul runtime .NET normale, non dentro un browser).
- **Nota — `Konscious.Security.Cryptography.Argon2.GetBytes()` (sincrono) non funziona in Blazor WASM**: un secondo bug della stessa categoria, trovato quando la pagina di login è stata verificata per la prima volta in un browser reale (Fase 1, non nei 134 test di `CffVaultManager.Crypto.Tests`, che girano sul runtime .NET normale). Il metodo sincrono blocca internamente su un `Task.Result`, che sotto il runtime single-thread `browser-wasm` lancia `PlatformNotSupportedException: Cannot wait on monitors on this runtime`. Il metodo asincrono `GetBytesAsync` non ha questo problema (un `await` reale cede il controllo al runtime invece di bloccare). `IKeyDerivationService` espone ora anche `DeriveKekAsync(string, ...)` (oltre al `DeriveKek(ReadOnlySpan<char>, ...)` sincrono già esistente, invariato e tuttora usato lato server dove il blocco funziona correttamente); il client Blazor (`Login.razor`) usa sempre la versione async. `Pbkdf2KeyDerivationService` non ha bisogno di questa distinzione: `Rfc2898DeriveBytes.Pbkdf2` è una computazione sincrona pura, senza alcuna attesa bloccante interna.
- Nonce/IV generati con `RandomNumberGenerator.Fill` (o equivalente), mai riutilizzati per la stessa chiave.
- Parametri Argon2id scelti bilanciando sicurezza e UX (tempo di derivazione target: ~300-500ms su hardware client medio).
- Chiavi (KEK, DEK in chiaro) devono avere lifetime minimo in memoria; azzerare i buffer dopo l'uso dove il linguaggio lo consente (`Span<byte>`, `CryptographicOperations.ZeroMemory`).

## Test richiesti

- Round-trip cifratura/decifratura per ogni tipo di payload.
- Verifica che chiave/nonce errati causino fallimento esplicito (AES-GCM tag mismatch) e non decifratura silenziosa corrotta.
- Test di non-regressione sui parametri Argon2id (cambiarli richiede una migration esplicita documentata).

## Stato

Implementato in `CffVaultManager.Crypto`: derivazione Argon2id (con la variante async `DeriveKekAsync` per compatibilità WASM, vedi sopra), generazione/cifratura DEK, `AesGcmCipherService` (ora su BouncyCastle per compatibilità WASM, vedi sopra), 139 test.

**Cambio master password**: procedura applicativa completa (Fase 2), non solo i primitivi — vedi [authentication.md](authentication.md) per l'endpoint/servizio. Ri-cifra solo la DEK come richiesto qui sopra: il client sblocca la DEK esistente con la vecchia KEK, ne deriva una nuova dalla nuova master password e ri-wrappa la stessa DEK, senza mai ri-cifrare un `VaultItem`.

Manca ancora: la rotazione DEK come procedura applicativa completa (i primitivi crittografici che le servirebbero esistono già — stesso `IDekService`/`IAeadCipherService` usati dal cambio master password).
