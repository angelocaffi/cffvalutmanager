using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// WebAuthn/FIDO2 as an MFA factor. Delegates all attestation/assertion cryptography to
/// <see cref="IFido2"/> (Fido2NetLib) rather than hand-rolling CBOR/COSE parsing and signature
/// verification — the same reasoning as using Konscious for Argon2id and Otp.NET for TOTP
/// elsewhere in this project: this is exactly the kind of security-critical parsing code that
/// should not be reimplemented per-project.
/// </summary>
internal sealed class WebAuthnService : IWebAuthnService
{
    private static readonly TimeSpan CeremonyLifetime = TimeSpan.FromMinutes(5);

    // Fixed, non-secret domain-separation salt for the WebAuthn PRF extension — set once here,
    // server-side, in both the passwordless-enrollment registration and every usernameless login
    // assertion, so the same credential always yields the same PRF output for the same salt (see
    // docs/security-model.md#sblocco-senza-password-via-passkey-webauthn-prf). Fido2NetLib
    // base64url-encodes it into the options JSON like challenge/user.id; webauthn.js decodes it
    // with the same helper it already uses for those — no client-side constant needed.
    private static readonly byte[] PasskeyPrfSalt = "CffVaultManager:PasskeyDekWrap:v1"u8.ToArray();

    private readonly CffVaultManagerDbContext _db;
    private readonly IFido2 _fido2;
    private readonly ISecurityNotificationService? _securityNotifications;
    private readonly ILogger<WebAuthnService>? _logger;

    public WebAuthnService(CffVaultManagerDbContext db, IFido2 fido2, ISecurityNotificationService? securityNotifications = null, ILogger<WebAuthnService>? logger = null)
    {
        _db = db;
        _fido2 = fido2;
        _securityNotifications = securityNotifications;
        _logger = logger;
    }

    public async Task<string> BeginRegistrationAsync(Guid userId, bool enablePasswordless = false, CancellationToken ct = default)
    {
        // Runs post-authentication, so the tenant query filter is resolved and correctly scopes
        // this to the caller's own user record (mirrors MfaSetupService/EmailOtpMfaService).
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        var excludeCredentials = await _db.WebAuthnCredentials
            .Where(c => c.UserId == userId)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync(ct);

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = userId.ToByteArray(),
                Name = user.Email,
                DisplayName = user.Email,
            },
            ExcludeCredentials = excludeCredentials,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                // Discoverable (resident) only for the passwordless-enrollment path — a normal
                // MFA-only credential stays non-discoverable, unchanged from before this feature.
                ResidentKey = enablePasswordless ? ResidentKeyRequirement.Required : ResidentKeyRequirement.Discouraged,
                UserVerification = UserVerificationRequirement.Preferred,
            },
            AttestationPreference = AttestationConveyancePreference.None,
            PubKeyCredParams = PubKeyCredParam.Defaults,
            Extensions = enablePasswordless
                ? new AuthenticationExtensionsClientInputs
                {
                    PRF = new AuthenticationExtensionsPRFInputs
                    {
                        Eval = new AuthenticationExtensionsPRFValues { First = PasskeyPrfSalt },
                    },
                }
                : null,
        });

        string optionsJson = options.ToJson();
        await ReplacePendingCeremonyAsync(userId, WebAuthnCeremonyPurpose.Registration, optionsJson, ct);
        return optionsJson;
    }

    public async Task<Guid> CompleteRegistrationAsync(Guid userId, string attestationResponseJson, string? nickname, byte[]? prfWrappedDek = null, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct)
            ?? throw new InvalidOperationException("User not found.");

        var ceremony = await GetPendingCeremonyAsync(userId, WebAuthnCeremonyPurpose.Registration, ct)
            ?? throw new InvalidOperationException("No pending registration ceremony for this user.");

        AuthenticatorAttestationRawResponse attestationResponse;
        try
        {
            attestationResponse = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(attestationResponseJson)
                ?? throw new InvalidOperationException("Invalid attestation response.");
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("Invalid attestation response.");
        }

        Fido2NetLib.Objects.RegisteredPublicKeyCredential result;
        try
        {
            result = await _fido2.MakeNewCredentialAsync(
                new MakeNewCredentialParams
                {
                    AttestationResponse = attestationResponse,
                    OriginalOptions = CredentialCreateOptions.FromJson(ceremony.OptionsJson),
                    IsCredentialIdUniqueToUserCallback = async (p, cbCt) =>
                        !await _db.WebAuthnCredentials.AnyAsync(c => c.CredentialId == p.CredentialId, cbCt),
                },
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Deliberately broad: this is fully attacker-controlled CBOR/ASN.1 input, and
            // Fido2NetLib does not guarantee every malformed shape surfaces as its own
            // Fido2VerificationException rather than a lower-level parsing exception (observed in
            // testing: a corrupted signature can throw ArgumentOutOfRangeException from its ASN.1
            // decoder, not Fido2VerificationException) — any failure here means "registration
            // could not be verified", never an unhandled 500.
            throw new InvalidOperationException("Attestation could not be verified.", ex);
        }

        ceremony.ConsumedAt = DateTimeOffset.UtcNow;

        var credential = new WebAuthnCredential(
            Guid.NewGuid(),
            userId,
            result.Id,
            result.PublicKey,
            result.SignCount,
            result.AaGuid,
            nickname,
            transports: result.Transports is { Length: > 0 }
                ? string.Join(",", result.Transports)
                : null,
            prfWrappedDek: prfWrappedDek);

        _db.WebAuthnCredentials.Add(credential);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, userId, AuditAction.WebAuthnCredentialRegistered));
        if (prfWrappedDek is not null)
        {
            _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, userId, AuditAction.PasskeyLoginEnabled));
        }

        await _db.SaveChangesAsync(ct);

        return credential.Id;
    }

    public async Task<IReadOnlyList<WebAuthnCredentialDto>> ListCredentialsAsync(Guid userId, CancellationToken ct = default)
    {
        // Materialized before ordering: the SQLite provider (used in tests) cannot translate
        // DateTimeOffset ordering to SQL — same fix as OneTimeCode-based services elsewhere.
        var credentials = await _db.WebAuthnCredentials
            .Where(c => c.UserId == userId)
            .Select(c => new WebAuthnCredentialDto(c.Id, c.Nickname, c.CreatedAt, c.LastUsedAt))
            .ToListAsync(ct);
        return credentials.OrderBy(c => c.CreatedAt).ToList();
    }

    public async Task RemoveCredentialAsync(Guid userId, Guid credentialId, CancellationToken ct = default)
    {
        var credential = await _db.WebAuthnCredentials.FirstOrDefaultAsync(c => c.Id == credentialId && c.UserId == userId, ct);
        if (credential is null)
        {
            return;
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);

        _db.WebAuthnCredentials.Remove(credential);
        if (user is not null)
        {
            _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, userId, AuditAction.WebAuthnCredentialRemoved));
        }

        await _db.SaveChangesAsync(ct);

        if (user is not null && _securityNotifications is not null)
        {
            await _securityNotifications.NotifyMfaFactorDisabledAsync(
                userId, credential.Nickname is null ? "una passkey" : $"la passkey \"{credential.Nickname}\"", ct);
        }
    }

    public async Task<string?> BeginAssertionAsync(Guid userId, CancellationToken ct = default)
    {
        // Called mid-login, before the tenant query filter can be resolved — but WebAuthnCredential
        // carries no query filter in the first place (mirrors RefreshToken), so no bypass is needed.
        var allowedCredentials = await _db.WebAuthnCredentials
            .Where(c => c.UserId == userId)
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToListAsync(ct);

        if (allowedCredentials.Count == 0)
        {
            return null;
        }

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials,
            UserVerification = UserVerificationRequirement.Preferred,
        });

        string optionsJson = options.ToJson();
        await ReplacePendingCeremonyAsync(userId, WebAuthnCeremonyPurpose.Assertion, optionsJson, ct);
        return optionsJson;
    }

    public async Task<bool> CompleteAssertionAsync(Guid userId, string assertionResponseJson, CancellationToken ct = default)
    {
        var ceremony = await GetPendingCeremonyAsync(userId, WebAuthnCeremonyPurpose.Assertion, ct);
        if (ceremony is null)
        {
            return false;
        }

        AuthenticatorAssertionRawResponse? assertionResponse;
        try
        {
            assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(assertionResponseJson);
        }
        catch (JsonException)
        {
            assertionResponse = null;
        }

        if (assertionResponse is null)
        {
            return false;
        }

        var credential = await _db.WebAuthnCredentials
            .FirstOrDefaultAsync(c => c.UserId == userId && c.CredentialId == assertionResponse.RawId, ct);
        if (credential is null)
        {
            return false;
        }

        VerifyAssertionResult result;
        try
        {
            result = await _fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    AssertionResponse = assertionResponse,
                    OriginalOptions = AssertionOptions.FromJson(ceremony.OptionsJson),
                    StoredPublicKey = credential.PublicKey,
                    StoredSignatureCounter = credential.SignCount,
                    IsUserHandleOwnerOfCredentialIdCallback = (p, _) =>
                        Task.FromResult(p.UserHandle.AsSpan().SequenceEqual(userId.ToByteArray())),
                },
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Bad signature, wrong origin/RP ID, replayed/regressed sign count, etc. — Fido2NetLib
            // usually signals this via Fido2VerificationException, but not always: a corrupted
            // signature can throw a lower-level parsing exception instead (observed in testing:
            // ArgumentOutOfRangeException from its ASN.1 decoder on a malformed DER signature).
            // This is fully attacker-controlled input, so every failure here — whatever its exact
            // type — is uniformly "assertion failed", never an unhandled 500.
            ceremony.ConsumedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(ct);
            return false;
        }

        ceremony.ConsumedAt = DateTimeOffset.UtcNow;
        credential.SignCount = result.SignCount;
        credential.LastUsedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);
        return true;
    }

    public async Task<PasskeyLoginCeremony> BeginPasskeyLoginAsync(CancellationToken ct = default)
    {
        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            // AllowedCredentials deliberately left unset: a usernameless assertion has no known
            // user to scope it to — the browser resolves candidates itself from any discoverable
            // credential it holds for this origin.
            UserVerification = UserVerificationRequirement.Preferred,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                PRF = new AuthenticationExtensionsPRFInputs
                {
                    Eval = new AuthenticationExtensionsPRFValues { First = PasskeyPrfSalt },
                },
            },
        });

        string optionsJson = options.ToJson();

        // No userId to key this ceremony by (unlike ReplacePendingCeremonyAsync's callers) — the
        // ceremony's own id is the only correlator, returned to the client and re-presented at
        // "complete", same principle as TenantProvisioningRequest's Id-as-token.
        var ceremonyId = Guid.NewGuid();
        _db.WebAuthnCeremonies.Add(new WebAuthnCeremony(
            ceremonyId, userId: null, WebAuthnCeremonyPurpose.PasskeyLogin, optionsJson, DateTimeOffset.UtcNow.Add(CeremonyLifetime)));
        await _db.SaveChangesAsync(ct);

        return new PasskeyLoginCeremony(ceremonyId, optionsJson);
    }

    public async Task<PasskeyLoginAssertionResult?> CompletePasskeyLoginAssertionAsync(Guid ceremonyId, string assertionResponseJson, CancellationToken ct = default)
    {
        var ceremony = await _db.WebAuthnCeremonies.FirstOrDefaultAsync(
            c => c.Id == ceremonyId && c.Purpose == WebAuthnCeremonyPurpose.PasskeyLogin && c.ConsumedAt == null, ct);
        if (ceremony is null || ceremony.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return null;
        }

        AuthenticatorAssertionRawResponse? assertionResponse;
        try
        {
            assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(assertionResponseJson);
        }
        catch (JsonException)
        {
            assertionResponse = null;
        }

        if (assertionResponse is null)
        {
            return null;
        }

        // No known user yet — the credential's own (globally unique) id is the only way to
        // discover who's logging in for a usernameless assertion, unlike CompleteAssertionAsync
        // above which already knows userId from the MFA challenge token.
        var credential = await _db.WebAuthnCredentials.FirstOrDefaultAsync(c => c.CredentialId == assertionResponse.RawId, ct);
        if (credential is null || credential.PrfWrappedDek is null)
        {
            return null;
        }

        VerifyAssertionResult result;
        try
        {
            result = await _fido2.MakeAssertionAsync(
                new MakeAssertionParams
                {
                    AssertionResponse = assertionResponse,
                    OriginalOptions = AssertionOptions.FromJson(ceremony.OptionsJson),
                    StoredPublicKey = credential.PublicKey,
                    StoredSignatureCounter = credential.SignCount,
                    IsUserHandleOwnerOfCredentialIdCallback = (p, _) =>
                        Task.FromResult(p.UserHandle.AsSpan().SequenceEqual(credential.UserId.ToByteArray())),
                },
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never logged before this line was added — every passwordless-login failure surfaced
            // to the client as an identical generic error with zero server-side diagnostic trail.
            // The exception itself (Fido2NetLib validation failures, signature/PRF-adjacent
            // mismatches) contains no secret material — the PRF output never reaches this class.
            _logger?.LogWarning(ex, "Passkey passwordless login assertion verification failed for credential {CredentialId}", credential.Id);
            ceremony.ConsumedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(ct);
            return null;
        }

        ceremony.ConsumedAt = DateTimeOffset.UtcNow;
        credential.SignCount = result.SignCount;
        credential.LastUsedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        return new PasskeyLoginAssertionResult(credential.UserId, credential.PrfWrappedDek);
    }

    private async Task<WebAuthnCeremony?> GetPendingCeremonyAsync(Guid userId, WebAuthnCeremonyPurpose purpose, CancellationToken ct)
    {
        // Materialized before ordering: the SQLite provider (used in tests) cannot translate
        // DateTimeOffset ordering to SQL — same fix as OneTimeCode-based services elsewhere.
        var ceremonies = await _db.WebAuthnCeremonies
            .Where(c => c.UserId == userId && c.Purpose == purpose && c.ConsumedAt == null)
            .ToListAsync(ct);
        var current = ceremonies.OrderByDescending(c => c.CreatedAt).FirstOrDefault();
        return current is not null && current.ExpiresAt > DateTimeOffset.UtcNow ? current : null;
    }

    // Only one ceremony of a given purpose is ever "current" for a user: starting a new one
    // (re-registering, or a fresh login attempt) supersedes any earlier pending one rather than
    // leaving it around to be confused with the new one.
    private async Task ReplacePendingCeremonyAsync(Guid userId, WebAuthnCeremonyPurpose purpose, string optionsJson, CancellationToken ct)
    {
        var pending = await _db.WebAuthnCeremonies
            .Where(c => c.UserId == userId && c.Purpose == purpose && c.ConsumedAt == null)
            .ToListAsync(ct);
        foreach (var stale in pending)
        {
            stale.ConsumedAt = DateTimeOffset.UtcNow;
        }

        _db.WebAuthnCeremonies.Add(new WebAuthnCeremony(
            Guid.NewGuid(), userId, purpose, optionsJson, DateTimeOffset.UtcNow.Add(CeremonyLifetime)));
        await _db.SaveChangesAsync(ct);
    }
}
