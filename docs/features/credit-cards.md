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

Da pianificare.
