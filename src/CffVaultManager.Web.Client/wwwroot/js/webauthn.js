// WebAuthn/Passkey browser interop. The server (Fido2NetLib) hands back CredentialCreateOptions/
// AssertionOptions JSON with byte fields (challenge, user.id, credential ids) already base64url
// -encoded — this module's only job is converting those to/from the ArrayBuffers
// navigator.credentials.create()/get() actually require, and back again for the response the
// server verifies. Every other property name here (rp, user, pubKeyCredParams,
// authenticatorSelection, excludeCredentials, allowCredentials, rpId, attestation,
// userVerification, type, alg) matches the WebAuthn spec's own JSON shape one-to-one, by design
// on the server side — nothing to translate for those.

function base64UrlToBuffer(base64url) {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
    const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
}

function bufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const b of bytes) {
        str += String.fromCharCode(b);
    }
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCredentialDescriptors(list) {
    if (!list) {
        return undefined;
    }
    return list.map(c => ({ ...c, id: base64UrlToBuffer(c.id) }));
}

export function isAvailable() {
    return typeof window.PublicKeyCredential !== "undefined";
}

export async function isPlatformAuthenticatorAvailable() {
    if (!isAvailable() || !window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
        return false;
    }

    try {
        return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
        return false;
    }
}

export async function register(optionsJson) {
    const options = JSON.parse(optionsJson);
    const publicKey = {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        user: { ...options.user, id: base64UrlToBuffer(options.user.id) },
        excludeCredentials: decodeCredentialDescriptors(options.excludeCredentials),
    };

    let credential;
    try {
        credential = await navigator.credentials.create({ publicKey });
    } catch (error) {
        // The C# side (WebAuthnJsInterop.RegisterAsync) collapses every JSException into the
        // same generic "registration failed" message for the user, so the actual DOMException
        // (name + message — e.g. NotAllowedError, SecurityError) would otherwise be lost. Logging
        // it here is often the only way to diagnose device-specific failures (passkey provider
        // conflicts, RP ID mismatches, etc.) without physical access to the failing device.
        console.error(`WebAuthn registration failed: ${error.name}: ${error.message}`);
        throw error;
    }

    return JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: bufferToBase64Url(credential.response.attestationObject),
            clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
        },
        clientExtensionResults: credential.getClientExtensionResults(),
    });
}

// --- Passwordless passkey login (WebAuthn PRF extension) ---------------------------------------
// See docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf. The PRF output is
// the client-side equivalent of the master password: it must NEVER be included in the JSON sent
// to the server. register()/authenticate() above always forward the full clientExtensionResults
// (Fido2NetLib deserializes it into a real, typed property server-side) — reusing them unmodified
// with the PRF extension merely added to the request would leak that secret. buildPrfResult below
// splits the browser's response into two independent values instead: a server-bound JSON string
// with `prf` stripped out of clientExtensionResults, and the PRF output kept separate — callers
// must keep the latter strictly client-side.

function decodePrfExtension(extensions) {
    const first = extensions?.prf?.eval?.first;
    if (!first) {
        return extensions;
    }
    return { ...extensions, prf: { eval: { first: base64UrlToBuffer(first) } } };
}

function buildPrfResult(credential, response) {
    const extensionResults = credential.getClientExtensionResults();
    const prfOutputBuffer = extensionResults?.prf?.results?.first ?? null;
    const { prf, ...otherExtensionResults } = extensionResults ?? {};

    const responseJson = JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response,
        clientExtensionResults: otherExtensionResults,
    });

    return {
        responseJson,
        // Null when the authenticator/browser doesn't support PRF (or didn't evaluate it) — the
        // caller must fall back to master-password login in that case, never treat this as success.
        prfOutput: prfOutputBuffer ? bufferToBase64Url(prfOutputBuffer) : null,
    };
}

export async function registerWithPrf(optionsJson) {
    const options = JSON.parse(optionsJson);
    const publicKey = {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        user: { ...options.user, id: base64UrlToBuffer(options.user.id) },
        excludeCredentials: decodeCredentialDescriptors(options.excludeCredentials),
        extensions: decodePrfExtension(options.extensions),
    };

    let credential;
    try {
        credential = await navigator.credentials.create({ publicKey });
    } catch (error) {
        console.error(`Passwordless passkey registration failed: ${error.name}: ${error.message}`);
        throw error;
    }

    return buildPrfResult(credential, {
        attestationObject: bufferToBase64Url(credential.response.attestationObject),
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
    });
}

export async function authenticateWithPrf(optionsJson) {
    const options = JSON.parse(optionsJson);
    const publicKey = {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        allowCredentials: decodeCredentialDescriptors(options.allowCredentials),
        extensions: decodePrfExtension(options.extensions),
    };

    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey });
    } catch (error) {
        console.error(`Passkey login failed: ${error.name}: ${error.message}`);
        throw error;
    }

    return buildPrfResult(credential, {
        authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
        clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
        signature: bufferToBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null,
    });
}

export async function authenticate(optionsJson) {
    const options = JSON.parse(optionsJson);
    const publicKey = {
        ...options,
        challenge: base64UrlToBuffer(options.challenge),
        allowCredentials: decodeCredentialDescriptors(options.allowCredentials),
    };

    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey });
    } catch (error) {
        console.error(`WebAuthn authentication failed: ${error.name}: ${error.message}`);
        throw error;
    }

    return JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            authenticatorData: bufferToBase64Url(credential.response.authenticatorData),
            clientDataJSON: bufferToBase64Url(credential.response.clientDataJSON),
            signature: bufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle ? bufferToBase64Url(credential.response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
    });
}
