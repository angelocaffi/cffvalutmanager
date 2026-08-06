namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>The options JSON for a usernameless WebAuthn assertion, plus the ceremony id the client must re-present at "complete" (there is no known user to look the pending ceremony up by).</summary>
public sealed record PasskeyLoginCeremony(Guid CeremonyId, string OptionsJson);
