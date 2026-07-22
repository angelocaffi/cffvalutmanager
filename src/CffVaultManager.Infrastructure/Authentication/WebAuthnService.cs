using System.Text.Json;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Entities;
using CffVaultManager.Domain.Enums;
using CffVaultManager.Infrastructure.Persistence;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;

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

    private readonly CffVaultManagerDbContext _db;
    private readonly IFido2 _fido2;
    private readonly ISecurityNotificationService? _securityNotifications;

    public WebAuthnService(CffVaultManagerDbContext db, IFido2 fido2, ISecurityNotificationService? securityNotifications = null)
    {
        _db = db;
        _fido2 = fido2;
        _securityNotifications = securityNotifications;
    }

    public async Task<string> BeginRegistrationAsync(Guid userId, CancellationToken ct = default)
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
                ResidentKey = ResidentKeyRequirement.Discouraged,
                UserVerification = UserVerificationRequirement.Preferred,
            },
            AttestationPreference = AttestationConveyancePreference.None,
            PubKeyCredParams = PubKeyCredParam.Defaults,
        });

        string optionsJson = options.ToJson();
        await ReplacePendingCeremonyAsync(userId, WebAuthnCeremonyPurpose.Registration, optionsJson, ct);
        return optionsJson;
    }

    public async Task<Guid> CompleteRegistrationAsync(Guid userId, string attestationResponseJson, string? nickname, CancellationToken ct = default)
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
                : null);

        _db.WebAuthnCredentials.Add(credential);
        _db.AuditLogEntries.Add(new AuditLogEntry(Guid.NewGuid(), user.TenantId, userId, AuditAction.WebAuthnCredentialRegistered));
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
