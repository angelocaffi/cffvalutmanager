using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;

namespace CffVaultManager.Api.Tests;

/// <summary>
/// A minimal virtual FIDO2 authenticator for tests: generates real, validly-signed
/// attestation/assertion responses (ECDSA P-256, "none" attestation format) so the real
/// Fido2NetLib integration wired up in the Api host gets exercised end-to-end over HTTP, not just
/// mocked around. There is no browser in a test run to drive <c>navigator.credentials</c>, so this
/// stands in for one — must sign for <see cref="ApiTestFactory.WebAuthnRpId"/>/<see cref="ApiTestFactory.WebAuthnOrigin"/>.
/// </summary>
internal sealed class FakeWebAuthnAuthenticator
{
    private const byte FlagUserPresent = 0b0000_0001;
    private const byte FlagUserVerified = 0b0000_0100;
    private const byte FlagAttestedCredentialData = 0b0100_0000;

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);

    public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public uint SignCount { get; set; } = 1;

    /// <summary>Builds a fake browser response to <c>navigator.credentials.create()</c> for the given server-issued options.</summary>
    public string CreateAttestationResponseJson(CredentialCreateOptions options, string origin)
    {
        byte[] clientDataJson = BuildClientDataJson("webauthn.create", options.Challenge, origin);
        byte[] authData = BuildAuthData(options.Rp.Id!, FlagUserPresent | FlagUserVerified | FlagAttestedCredentialData, SignCount, BuildAttestedCredentialData());
        byte[] attestationObject = BuildAttestationObject(authData);

        return JsonSerializer.Serialize(new
        {
            id = Base64Url(CredentialId),
            rawId = Base64Url(CredentialId),
            type = "public-key",
            response = new
            {
                attestationObject = Base64Url(attestationObject),
                clientDataJSON = Base64Url(clientDataJson),
            },
            clientExtensionResults = new { },
        });
    }

    /// <summary>Builds a fake browser response to <c>navigator.credentials.get()</c> for the given server-issued options.</summary>
    public string CreateAssertionResponseJson(AssertionOptions options, string origin, byte[] userHandle, byte flagsOverride = FlagUserPresent | FlagUserVerified)
    {
        byte[] clientDataJson = BuildClientDataJson("webauthn.get", options.Challenge, origin);
        byte[] authData = BuildAuthData(options.RpId!, flagsOverride, SignCount, attestedCredentialData: null);
        byte[] signature = SignAssertion(authData, clientDataJson);

        return JsonSerializer.Serialize(new
        {
            id = Base64Url(CredentialId),
            rawId = Base64Url(CredentialId),
            type = "public-key",
            response = new
            {
                authenticatorData = Base64Url(authData),
                clientDataJSON = Base64Url(clientDataJson),
                signature = Base64Url(signature),
                userHandle = Base64Url(userHandle),
            },
            clientExtensionResults = new { },
        });
    }

    private byte[] SignAssertion(byte[] authData, byte[] clientDataJson)
    {
        byte[] clientDataHash = SHA256.HashData(clientDataJson);
        byte[] signedData = new byte[authData.Length + clientDataHash.Length];
        authData.CopyTo(signedData, 0);
        clientDataHash.CopyTo(signedData, authData.Length);
        return KeyPair.SignData(signedData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static byte[] BuildClientDataJson(string type, byte[] challenge, string origin)
    {
        var json = JsonSerializer.Serialize(new
        {
            type,
            challenge = Base64Url(challenge),
            origin,
            crossOrigin = false,
        });
        return Encoding.UTF8.GetBytes(json);
    }

    private static byte[] BuildAuthData(string rpId, byte flags, uint signCount, byte[]? attestedCredentialData)
    {
        byte[] rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        using var stream = new MemoryStream();
        stream.Write(rpIdHash);
        stream.WriteByte(flags);
        stream.Write(new[] { (byte)(signCount >> 24), (byte)(signCount >> 16), (byte)(signCount >> 8), (byte)signCount });
        if (attestedCredentialData is not null)
        {
            stream.Write(attestedCredentialData);
        }

        return stream.ToArray();
    }

    private byte[] BuildAttestedCredentialData()
    {
        using var stream = new MemoryStream();
        stream.Write(new byte[16]); // AAGUID: zeroed out, not asserted on by any test here.
        stream.WriteByte((byte)(CredentialId.Length >> 8));
        stream.WriteByte((byte)CredentialId.Length);
        stream.Write(CredentialId);
        stream.Write(BuildCoseP256PublicKey());
        return stream.ToArray();
    }

    private byte[] BuildCoseP256PublicKey()
    {
        var parameters = KeyPair.ExportParameters(includePrivateParameters: false);
        var writer = new CborWriter();
        writer.WriteStartMap(5);
        writer.WriteInt32(1); writer.WriteInt32(2);   // kty: EC2
        writer.WriteInt32(3); writer.WriteInt32(-7);  // alg: ES256
        writer.WriteInt32(-1); writer.WriteInt32(1);  // crv: P-256
        writer.WriteInt32(-2); writer.WriteByteString(parameters.Q.X!);
        writer.WriteInt32(-3); writer.WriteByteString(parameters.Q.Y!);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] BuildAttestationObject(byte[] authData)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
