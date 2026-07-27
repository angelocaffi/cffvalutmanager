namespace CffVaultManager.Application.Dtos.Billing;

public sealed record CaptureCheckoutResult(bool Success, DateTimeOffset? PlanExpiresAt);
