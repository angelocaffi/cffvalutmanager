namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The Argon2id parameters a client needs to re-derive its own KEK before logging in from a
/// device that has never cached them. Never a secret in itself (comparable to a bcrypt salt) —
/// but the response for an unknown email must still be indistinguishable from a real one, so an
/// attacker cannot use this endpoint to enumerate registered addresses.
/// </summary>
public sealed record PreloginResult(byte[] MasterPasswordSalt, int KdfMemoryKb, int KdfIterations, int KdfVersion);
