using System.Net;

namespace CffVaultManager.Crypto.Tests;

/// <summary>Test double standing in for the real network — captures the outgoing request and returns a canned response.</summary>
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _statusCode;
    private readonly string _responseBody;

    public HttpRequestMessage? LastRequest { get; private set; }

    public FakeHttpMessageHandler(string responseBody, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _responseBody = responseBody;
        _statusCode = statusCode;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        LastRequest = request;
        var response = new HttpResponseMessage(_statusCode) { Content = new StringContent(_responseBody) };
        return Task.FromResult(response);
    }
}
