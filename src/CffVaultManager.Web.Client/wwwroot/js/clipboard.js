// Copies text to the clipboard, then overwrites it with an empty string after a delay — the
// "auto-clear appunti" requirement for password/CVV/card-number/private-key/seed-phrase copies
// (docs/features/password-manager.md, credit-cards.md, crypto-wallets.md). Best-effort: if the
// clipboard still holds what we wrote (the user hasn't copied anything else meanwhile), we
// overwrite it; if the user already copied something new, we quietly leave it alone.

export async function copyWithAutoClear(text, clearAfterMs) {
    await navigator.clipboard.writeText(text);

    setTimeout(async () => {
        try {
            const current = await navigator.clipboard.readText();
            if (current === text) {
                await navigator.clipboard.writeText("");
            }
        } catch {
            // Clipboard read can be denied by the browser (permissions/focus) — nothing to do.
        }
    }, clearAfterMs);
}
