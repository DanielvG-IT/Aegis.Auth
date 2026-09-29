using System.Net;

using Aegis.Auth.Constants;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Tests.Http;

public sealed class OAuthPkceTests
{
    private static void EnableAllProviders(AegisAuthOptions o)
    {
        o.OAuth.AddGoogle("google-id", "google-secret");
        o.OAuth.AddGitHub("github-id", "github-secret");
        o.OAuth.AddMicrosoft("microsoft-id", "microsoft-secret");
        o.OAuth.AddApple("apple-id", "apple-secret");
    }

    private static async Task<Dictionary<string, Microsoft.Extensions.Primitives.StringValues>> ChallengeQueryAsync(AegisTestHost host, string provider)
    {
        HttpResponseMessage response = await host.Client.GetAsync($"/api/auth/sign-in/oauth/{provider}");
        Assert.True(response.StatusCode == HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync());
        Uri location = response.Headers.Location!;
        return QueryHelpers.ParseQuery(location.Query);
    }

    [Theory]
    [InlineData(AegisAuthProviders.Google)]
    [InlineData(AegisAuthProviders.GitHub)]
    [InlineData(AegisAuthProviders.Microsoft)]
    [InlineData(AegisAuthProviders.Apple)]
    public async Task AuthorizationRedirect_IncludesS256CodeChallenge(string provider)
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(EnableAllProviders);

        var query = await ChallengeQueryAsync(host, provider);

        Assert.True(query.ContainsKey("code_challenge"), $"{provider} redirect is missing code_challenge");
        Assert.Equal("S256", query["code_challenge_method"].ToString());
    }

    [Fact]
    public async Task UsePkceFalse_OmitsCodeChallenge()
    {
        await using AegisTestHost host = await AegisTestHost.StartAsync(o =>
            o.OAuth.AddGoogle("google-id", "google-secret", google => google.UsePkce = false));

        var query = await ChallengeQueryAsync(host, AegisAuthProviders.Google);

        Assert.False(query.ContainsKey("code_challenge"));
    }

    [Fact]
    public async Task UsePkceFalse_LogsStartupWarning()
    {
        var logs = new ListLoggerProvider();
        await using AegisTestHost host = await AegisTestHost.StartAsync(
            o => o.OAuth.AddGitHub("github-id", "github-secret", gitHub => gitHub.UsePkce = false),
            configureServices: s => s.AddLogging(b => b.AddProvider(logs)));

        Assert.Contains(logs.Messages, m => m.Level == LogLevel.Warning && m.Text.Contains("PKCE is disabled for the GitHub"));
    }

    [Fact]
    public async Task DefaultConfiguration_LogsNoPkceWarning()
    {
        var logs = new ListLoggerProvider();
        await using AegisTestHost host = await AegisTestHost.StartAsync(
            EnableAllProviders,
            configureServices: s => s.AddLogging(b => b.AddProvider(logs)));

        Assert.DoesNotContain(logs.Messages, m => m.Text.Contains("PKCE"));
    }

    private sealed class ListLoggerProvider : ILoggerProvider
    {
        public List<(LogLevel Level, string Text)> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new ListLogger(Messages);

        public void Dispose() { }

        private sealed class ListLogger(List<(LogLevel, string)> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (messages)
                {
                    messages.Add((logLevel, formatter(state, exception)));
                }
            }
        }
    }
}
