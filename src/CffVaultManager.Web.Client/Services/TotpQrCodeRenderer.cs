using QRCoder;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Renders a TOTP <c>otpauth://</c> provisioning URI as a scannable QR code, entirely client-side
/// (QRCoder's <see cref="SvgQRCode"/> is pure string manipulation, no System.Drawing/imaging
/// dependency, so it runs fine under Blazor WASM). The URI carries the TOTP secret, so it is never
/// sent anywhere for rendering — unlike e.g. a third-party QR-image API, which would leak the
/// secret over the network.
/// </summary>
public static class TotpQrCodeRenderer
{
    public static string ToSvg(string provisioningUri)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(provisioningUri, QRCodeGenerator.ECCLevel.Q);
        var svgQrCode = new SvgQRCode(data);
        return svgQrCode.GetGraphic(pixelsPerModule: 5);
    }

    /// <summary>Extracts the base32 <c>secret</c> query parameter, for manual entry when scanning isn't possible.</summary>
    public static string? ExtractSecret(string provisioningUri)
    {
        int queryStart = provisioningUri.IndexOf('?');
        if (queryStart < 0)
        {
            return null;
        }

        foreach (string pair in provisioningUri[(queryStart + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq > 0 && pair[..eq] == "secret")
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        return null;
    }
}
