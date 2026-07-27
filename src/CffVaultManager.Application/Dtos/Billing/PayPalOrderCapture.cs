namespace CffVaultManager.Application.Dtos.Billing;

/// <summary>Result of capturing a PayPal order — <see cref="Status"/> is the raw PayPal status string (e.g. <c>COMPLETED</c>).</summary>
public sealed record PayPalOrderCapture(string Status, string CaptureId);
