using CffVaultManager.Domain.Entities;

namespace CffVaultManager.Application.Dtos.Authentication;

/// <summary>
/// The result of issuing a refresh token. <see cref="PlainToken"/> is the only copy of the
/// clear-text token and is never persisted (the database only holds its hash on
/// <see cref="RefreshToken.TokenHash"/>); it must be handed to the client and then dropped.
/// </summary>
public sealed record IssuedRefreshToken(string PlainToken, RefreshToken Entity);
