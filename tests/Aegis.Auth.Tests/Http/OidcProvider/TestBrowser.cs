using System.Net;
using System.Net.Http.Json;

using Microsoft.AspNetCore.TestHost;

namespace Aegis.Auth.Tests.Http.OidcProvider;

/// <summary>
/// A minimal user agent spanning several TestServers: one cookie jar, requests routed by host,
/// and redirects followed across hosts the way a browser would.
/// </summary>
internal sealed class TestBrowser : IDisposable
{
    private const int MaxRedirects = 20;

    private readonly Dictionary<string, HttpMessageInvoker> _hosts = new(StringComparer.OrdinalIgnoreCase);

    public CookieContainer Cookies { get; } = new();

    public void AddHost(TestServer server)
    {
        _hosts[server.BaseAddress.Authority] = new HttpMessageInvoker(server.CreateHandler());
    }

    /// <summary>
    /// GETs <paramref name="uri"/> and follows redirects. Stops early and returns the redirect
    /// response when <paramref name="stopAt"/> matches its target, or when the target is a host
    /// this browser doesn't know (for example an attacker's redirect URI).
    /// </summary>
    public async Task<HttpResponseMessage> GetAsync(Uri uri, Func<Uri, bool>? stopAt = null)
    {
        for (var i = 0; i < MaxRedirects; i++)
        {
            HttpResponseMessage response = await SendAsync(new HttpRequestMessage(HttpMethod.Get, uri));
            if (response.Headers.Location is not { } location || (int)response.StatusCode is < 300 or >= 400)
            {
                return response;
            }

            Uri next = location.IsAbsoluteUri ? location : new Uri(uri, location);
            if (stopAt?.Invoke(next) is true || _hosts.ContainsKey(next.Authority) is false)
            {
                return response;
            }

            response.Dispose();
            uri = next;
        }

        throw new InvalidOperationException($"More than {MaxRedirects} redirects.");
    }

    public Task<HttpResponseMessage> PostJsonAsync(Uri uri, object body)
        => SendAsync(new HttpRequestMessage(HttpMethod.Post, uri) { Content = JsonContent.Create(body) });

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
    {
        Uri uri = request.RequestUri ?? throw new ArgumentException("Absolute request URI required.", nameof(request));
        if (_hosts.TryGetValue(uri.Authority, out HttpMessageInvoker? invoker) is false)
        {
            throw new InvalidOperationException($"No test server registered for {uri.Authority}.");
        }

        var cookieHeader = Cookies.GetCookieHeader(uri);
        if (cookieHeader.Length > 0)
        {
            request.Headers.Add("Cookie", cookieHeader);
        }

        HttpResponseMessage response = await invoker.SendAsync(request, CancellationToken.None);
        if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? setCookies))
        {
            foreach (var setCookie in setCookies)
            {
                Cookies.SetCookies(uri, setCookie);
            }
        }

        return response;
    }

    public void Dispose()
    {
        foreach (HttpMessageInvoker invoker in _hosts.Values)
        {
            invoker.Dispose();
        }
    }
}
