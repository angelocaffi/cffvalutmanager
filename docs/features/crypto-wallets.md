# Gestione crypto wallet

## Scopo

Memorizzazione sicura di secrets relativi a wallet di criptovalute (indirizzi, chiavi private, seed phrase) per uso personale. Come per [credit-cards.md](credit-cards.md), questo modulo è puramente un vault di secrets — non firma transazioni, non si connette a nodi/blockchain, non è un wallet operativo.

## Requisiti funzionali

- CRUD voce wallet: Nome/Etichetta, Rete (Bitcoin/Ethereum/Litecoin/altro), Indirizzo pubblico, Chiave privata **[cifrato]**, Seed phrase / mnemonic **[cifrato]**, Note **[cifrato]**.
- **Riconoscimento automatico della rete** dal formato dell'indirizzo (client-side, solo per UX — icona Bitcoin/Ethereum/ecc.), come il riconoscimento circuito delle carte.
- **Validazione di plausibilità** di indirizzo e seed phrase, per intercettare errori di battitura prima della cifratura — non sostituisce la validazione del checksum reale della rete (vedi sotto).
- Associazione opzionale di più indirizzi allo stesso wallet (es. address di ricezione multipli per lo stesso seed).

## Requisiti di sicurezza

- Chiave privata e seed phrase **[cifrato]** con la stessa DEK del vault, mai persistite in chiaro né loggate — sono il secret a più alto valore dell'intero vault (compromissione = perdita totale dei fondi), quindi vanno trattate con lo stesso rigore di password/CVV.
- "Reveal" di chiave privata o seed phrase richiede conferma esplicita (vedi [audit-log.md](audit-log.md): ogni reveal genera un evento `Revealed` tramite `POST /api/vaults/{vaultId}/items/{itemId}/reveal`, esattamente come per password e numero carta).
- La validazione client-side (formato indirizzo, conteggio parole della seed phrase) è euristica e **non** costituisce una verifica crittografica: non implementa il checksum Base58Check/bech32 degli indirizzi né il checksum BIP-39 della seed phrase (richiederebbe la wordlist canonica BIP-39 a 2048 parole in ordine esatto — vedi nota in "Stato"). Non deve mai dare un falso senso di sicurezza: un indirizzo "plausibile" non è garantito valido.
- Nessuna integrazione con nodi blockchain, wallet software o exchange in questa fase — coerente con l'analogo vincolo PCI-DSS per le carte (vedi [../security-model.md](../security-model.md)).

## UX essenziale

- Vista "a wallet" con indirizzo mascherato di default (mostra solo alcuni caratteri, come le carte).
- Copia rapida di indirizzo/chiave privata/seed phrase con auto-clear appunti.
- Badge rete (icona Bitcoin/Ethereum/Litecoin) da riconoscimento automatico.

## Stato

- CRUD lato server: coperto genericamente dagli endpoint `vault-core` (nuovo valore `VaultItemType.CryptoWallet`, nessuna migrazione necessaria — l'enum è persistito come stringa, esattamente come per Password/CreditCard/SecureNote/GenericSecret). Cestino, cartelle, tag, preferiti e audit log (Created/Viewed/Updated/Deleted/Revealed) funzionano immediatamente per questo nuovo tipo, senza alcuna modifica aggiuntiva — è l'intero punto del design generico di `VaultItem`.
- Utility client-side implementate in `CffVaultManager.Crypto.CryptoWalletValidationService`: `DetectNetwork` (euristica da prefisso: `0x` per Ethereum, `1`/`3`/`bc1` per Bitcoin, `L`/`ltc1` per Litecoin), `IsPlausibleAddress` (controllo di lunghezza/charset, non un vero checksum), `IsPlausibleMnemonicWordCount` (verifica che il conteggio parole sia uno tra 12/15/18/21/24 come da BIP-39), `MaskSecret` (mascheramento generico, riusabile per indirizzo/chiave privata). 37 test unitari.
- **Deliberatamente non implementato**: validazione completa BIP-39 (verifica che ogni parola appartenga alla wordlist canonica + checksum crittografico) e validazione del checksum reale degli indirizzi (Base58Check per Bitcoin/Litecoin, EIP-55 per Ethereum). La wordlist BIP-39 richiede l'elenco esatto delle 2048 parole nell'ordine canonico: riprodurlo da fonti non verificabili in modo affidabile in questo ambiente avrebbe rischiato di introdurre un controllo di sicurezza silenziosamente errato, peggio che non averlo. Se servirà in futuro, va importata da una fonte verificata (es. libreria NuGet dedicata o il file ufficiale del repository `bitcoin/bips`) e testata contro i vettori di test ufficiali BIP-39, non scritta a mano.
- Da fare: pagine Blazor (`Web.Client`) per creare/vedere/modificare le voci wallet, cifratura/decifratura del payload lato client, conferma esplicita per il reveal di chiave privata/seed phrase, eventuale validazione crittografica completa (vedi punto sopra).
