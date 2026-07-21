# Gestione carte di credito

## Scopo

Memorizzazione sicura di dati di carte di pagamento per uso personale (non elaborazione pagamenti).

## Requisiti funzionali

- CRUD voce carta: Intestatario, Numero carta **[cifrato]**, Scadenza (mese/anno), CVV **[cifrato]**, Circuito (Visa/Mastercard/Amex/altro), Note **[cifrato]**.
- **Mascheramento di default**: mostra solo ultime 4 cifre del numero carta; CVV sempre nascosto salvo reveal esplicito.
- **Alert di scadenza**: notifica configurabile N giorni prima della scadenza (collegato a [notifications.md](notifications.md), v2).
- Riconoscimento automatico del circuito dal prefisso del numero carta (client-side, solo per UX — icona Visa/Mastercard/ecc.).

## Requisiti di sicurezza

- Numero carta e CVV **[cifrato]** con la stessa DEK del vault, mai persistiti in chiaro né loggati.
- Validazione formale del numero carta (algoritmo di Luhn) fatta **client-side prima della cifratura**, per non dover mai decifrare per validare.
- "Reveal" del numero carta completo o del CVV richiede conferma esplicita (es. re-inserimento master password o timeout breve di validità).
- Nessuna integrazione diretta con circuiti di pagamento/PSP in questa fase — il modulo è puramente un vault, non un wallet di pagamento. Se in futuro si aggiunge il pagamento reale, rivedere la conformità **PCI-DSS** (vedi [../security-model.md](../security-model.md)).

## UX essenziale

- Visualizzazione "a carta" (card UI) con numero mascherato, simile a wallet digitali.
- Copia rapida numero carta/CVV con auto-clear appunti.
- Badge visivo se la carta è in scadenza entro 30 giorni.

## Stato

- CRUD lato server: già coperto genericamente dagli endpoint `vault-core` (`VaultItem` con `Type = CreditCard`); nessun modello dati dedicato, il payload tipizzato (Intestatario, Numero carta, Scadenza, CVV, Circuito, Note) vive interamente dentro `EncryptedPayload` lato client, come da [data-model.md](../data-model.md).
- Utility client-side implementate in `CffVaultManager.Crypto.CardValidationService`: `IsValidCardNumber` (algoritmo di Luhn, tollerante a spazi/trattini, non lancia mai eccezioni su input malformato — pensato per validazione live del form), `DetectBrand` (riconoscimento Visa/Mastercard/Amex/Discover/Diners/JCB/UnionPay da prefisso numerico, solo euristica UX), `MaskCardNumber` (mascheramento di tutte le cifre tranne le ultime 4, raggruppate a blocchi di 4). 29 test unitari, inclusi numeri di test pubblici noti (Stripe/PayPal sandbox).
- Pagine Blazor (`Web.Client`): `Shared/CreditCardFields.razor` (dentro `VaultItemDetail.razor`, condiviso con password/wallet) mostra una vista "a carta" (numero mascherato, intestatario, scadenza), riconoscimento circuito live mentre si digita, validazione Luhn live con avviso visivo, badge "In scadenza" se la scadenza è entro 30 giorni. Reveal di numero completo/CVV: conferma esplicita (pulsante "Mostra", non un click accidentale) con finestra di validità breve (auto-nascondimento dopo 15s, come da opzione "timeout breve" prevista dal requisito), copia con auto-clear appunti — entrambe le azioni tracciate come evento `Revealed`. Alert di scadenza (notifica, v2) resta rimandato a [notifications.md](notifications.md); il badge visivo puramente informativo è invece implementato ora. Verificato dal vivo in un browser reale con un vero round-trip di cifratura/decifratura.
