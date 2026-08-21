// Service worker (Manifest V3) — terminated by Chrome after ~30s of inactivity, so nothing kept
// in module-level variables here survives that (see docs/security-model.md "Estensione browser").
// Fase 3: solo il ciclo di vita del documento offscreen e un round-trip di test attraverso il vero
// host crypto .NET, per verificare che l'avvio di Blazor WASM dentro un documento offscreen
// funzioni davvero prima di costruire login/cattura reali (fasi 4/5).

const OFFSCREEN_DOCUMENT_PATH = "offscreen/offscreen.html";

async function hasOffscreenDocument() {
  const contexts = await chrome.runtime.getContexts({
    contextTypes: ["OFFSCREEN_DOCUMENT"],
    documentUrls: [chrome.runtime.getURL(OFFSCREEN_DOCUMENT_PATH)],
  });
  return contexts.length > 0;
}

async function ensureOffscreenDocument() {
  if (await hasOffscreenDocument()) {
    return;
  }
  await chrome.offscreen.createDocument({
    url: OFFSCREEN_DOCUMENT_PATH,
    // "DOM_SCRAPING" è il motivo dell'API offscreen più vicino disponibile: nessuno scraping
    // avviene davvero, il documento serve solo a ospitare il runtime Blazor WASM (che non può
    // girare in un service worker) — vedi docs/security-model.md.
    reasons: ["DOM_SCRAPING"],
    justification:
      "Ospita il modulo crypto Blazor WebAssembly (Argon2id/AES-GCM/X25519): WASM non gira in un service worker.",
  });
}

async function closeOffscreenDocument() {
  if (await hasOffscreenDocument()) {
    await chrome.offscreen.closeDocument();
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.target !== "background") {
    return false;
  }

  if (message.type === "OPEN_CRYPTO_HOST") {
    ensureOffscreenDocument()
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message.type === "CLOSE_CRYPTO_HOST") {
    closeOffscreenDocument()
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message.type === "PING_CRYPTO_HOST") {
    ensureOffscreenDocument()
      .then(() => chrome.runtime.sendMessage({ target: "offscreen", type: "PING" }))
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  return false;
});
