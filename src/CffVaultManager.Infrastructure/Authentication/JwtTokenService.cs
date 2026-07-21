using System.Text;
using CffVaultManager.Application.Abstractions;
using CffVaultManager.Application.Dtos.Authentication;
using CffVaultManager.Domain.Enums;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CffVaultManager.Infrastructure.Authentication;

/// <summary>
/// Issues and validates JWTs signed with a symmetric key from configuration
/// (<c>Jwt:SigningKey</c>). In production this key must come from a managed secret store,
/// never a committed appsettings file.
/// </summary>
internal sealed class JwtTokenService : IJwtTokenService
{
    public const string MfaChallengePurpose = "mfa_challenge";

    private const string Issuer = "CffVaultManager";
    private const string Audience = "CffVaultManager";

    private readonly SymmetricSecurityKey _signingKey;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtTokenService(IConfiguration configuration)
    {
        string? key = configuration["Jwt:SigningKey"];
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new InvalidOperationException("Jwt:SigningKey is not configured.");
        }

        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    }

    public string CreateAccessToken(Guid userId, Guid? tenantId, UserRole role, TimeSpan lifetime, string? purpose = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = userId.ToString(),
            ["role"] = role.ToString(),
            ["jti"] = Guid.NewGuid().ToString(),
        };

        if (tenantId is { } tid)
        {
            claims["tenant_id"] = tid.ToString();
        }

        if (purpose is not null)
        {
            claims["purpose"] = purpose;
        }

        return CreateToken(claims, lifetime);
    }

    public string CreateMfaChallengeToken(Guid userId, TimeSpan lifetime)
    {
        // Deliberately no tenant_id / role: a stolen challenge token must not confer any access.
        var claims = new Dictionary<string, object>
        {
            ["sub"] = userId.ToString(),
            ["purpose"] = MfaChallengePurpose,
            ["jti"] = Guid.NewGuid().ToString(),
        };

        return CreateToken(claims, lifetime);
    }

    public async Task<JwtClaims?> ValidateAsync(string token, string? expectedPurpose = null)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            IssuerSigningKey = _signingKey,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        var result = await _handler.ValidateTokenAsync(token, parameters);
        if (!result.IsValid)
        {
            return null;
        }

        var claims = result.Claims;
        string? purpose = GetString(claims, "purpose");
        if (expectedPurpose is not null && !string.Equals(purpose, expectedPurpose, StringComparison.Ordinal))
        {
            return null;
        }

        string? sub = GetString(claims, "sub");
        if (sub is null || !Guid.TryParse(sub, out var userId))
        {
            return null;
        }

        Guid? tenantId = Guid.TryParse(GetString(claims, "tenant_id"), out var tid) ? tid : null;
        UserRole? role = Enum.TryParse<UserRole>(GetString(claims, "role"), out var r) ? r : null;

        return new JwtClaims(userId, tenantId, role, purpose);
    }

    private string CreateToken(Dictionary<string, object> claims, TimeSpan lifetime)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(lifetime),
            Claims = claims,
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256),
        };

        return _handler.CreateToken(descriptor);
    }

    private static string? GetString(IDictionary<string, object> claims, string key) =>
        claims.TryGetValue(key, out var value) ? value as string ?? value?.ToString() : null;
}
