// Reads/writes the URL fragment (the part after '#'), which per HTTP spec is never sent to the
// server — used to carry the external-share-link decryption key without ever exposing it to the
// backend (see docs/features/sharing-access-control.md "Link di condivisione esterna").

export function getHash() {
    return window.location.hash.startsWith('#') ? window.location.hash.substring(1) : window.location.hash;
}

export function setHash(value) {
    window.location.hash = value;
}
