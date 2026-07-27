namespace CffVaultManager.Application.Dtos.Billing;

/// <summary>The PayPal order id to hand to the client-side Smart Buttons SDK.</summary>
public sealed record CreateCheckoutResult(string OrderId);
