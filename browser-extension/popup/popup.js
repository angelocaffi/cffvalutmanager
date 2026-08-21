const statusEl = document.getElementById("status");

function send(type) {
  statusEl.textContent = "...";
  chrome.runtime.sendMessage({ target: "background", type }, (response) => {
    statusEl.textContent = JSON.stringify(response ?? chrome.runtime.lastError, null, 2);
  });
}

document.getElementById("open").addEventListener("click", () => send("OPEN_CRYPTO_HOST"));
document.getElementById("ping").addEventListener("click", () => send("PING_CRYPTO_HOST"));
document.getElementById("close").addEventListener("click", () => send("CLOSE_CRYPTO_HOST"));
