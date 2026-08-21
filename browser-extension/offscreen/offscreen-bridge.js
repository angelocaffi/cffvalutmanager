// Ponte tra il documento offscreen e il resto dell'estensione. Non tiene mai stato sensibile:
// ogni chiamata riceve tutto il materiale che le serve (master password, DEK, ecc.) dal
// chiamante e restituisce solo il risultato — vedi CryptoInterop.cs e
// docs/security-model.md "Estensione browser".

const ASSEMBLY = "CffVaultManager.Extension.CryptoHost";

const readyPromise = Blazor.start();

function randomBase64Key() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

async function pingCryptoHost() {
  await readyPromise;

  // Round-trip reale attraverso CryptoInterop (non solo un ping JS) per verificare che il
  // runtime .NET dentro il documento offscreen sia davvero utilizzabile prima di costruire
  // login/cattura reali sopra — chiave e testo usati solo per questo test, mai persistiti.
  const key = randomBase64Key();
  const plaintext = btoa("cffvault-offscreen-ping");

  const encrypted = await DotNet.invokeMethodAsync(ASSEMBLY, "Encrypt", plaintext, key);
  const decrypted = await DotNet.invokeMethodAsync(ASSEMBLY, "Decrypt", encrypted, key);

  return { ok: atob(decrypted) === "cffvault-offscreen-ping" };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.target !== "offscreen") {
    return false;
  }

  if (message.type === "PING") {
    // pingCryptoHost() awaits readyPromise itself — non rispondere subito "non pronto" solo
    // perché il boot di Blazor non è ancora finito, il chiamante aspetta la risposta reale.
    pingCryptoHost()
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  return false;
});
