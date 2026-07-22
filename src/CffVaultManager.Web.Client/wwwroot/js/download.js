// Triggers a browser file download from in-memory text content — used for the encrypted vault
// backup export (docs/features/import-export.md). No filesystem API exists for Blazor WASM to
// write a file directly, so this is the standard Blob + object URL + synthetic click pattern.

export function downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
