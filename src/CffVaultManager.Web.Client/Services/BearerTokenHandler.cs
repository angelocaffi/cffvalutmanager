using System.Net.Http.Headers;

namespace CffVaultManager.Web.Client.Services;

/// <summary>
/// Attaches the current access token (if any) to every outgoing request on the "Api"
/// <see cref="HttpClient"/>. Does not attempt a silent refresh on a 401 yet — a follow-up once
/// more pages exist and the pattern of "session expired mid-use" is actually hit in practice.
/// </summary>
public sealed class BearerTokenHandler : DelegatingHandler
{
    private readonly SessionState _session;

    public BearerTokenHandler(SessionState session) => _session = session;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_session.AccessToken is { } token)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return base.SendAsync(request, cancellationToken);
    }
}
