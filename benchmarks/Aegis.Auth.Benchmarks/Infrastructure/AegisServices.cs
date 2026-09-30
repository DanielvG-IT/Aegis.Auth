using Aegis.Auth.Extensions;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace Aegis.Auth.Benchmarks.Infrastructure;

/// <summary>
/// The container a consumer's app builds with <c>AddAegisAuth</c>, without a web host: benchmarks create a scope and
/// a <see cref="DefaultHttpContext"/> per operation, which is what the ASP.NET Core pipeline does per request.
/// </summary>
internal static class AegisServices
{
    public const string Secret = "benchmark-secret-that-is-long-enough-for-hmac-256!!";

    public static ServiceProvider Build(BenchDatabase database, Action<AegisAuthOptions>? configure = null, Action<IServiceCollection>? configureServices = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHostEnvironment>(new ProductionEnvironment());
        services.AddDbContext<BenchDbContext>(database.Configure);
        services.AddAegisAuth<BenchDbContext>(options =>
        {
            options.AppName = "Aegis.Auth.Benchmarks";
            options.BaseURL = "https://bench.aegis.local";
            options.Secret = Secret;
            options.RateLimit.Enabled = false;
            configure?.Invoke(options);
        });
        configureServices?.Invoke(services);

        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    /// <summary>
    /// Turns the <c>Set-Cookie</c> headers of a response into the <c>Cookie</c> header a browser would send back.
    /// </summary>
    public static string ToRequestCookieHeader(HttpResponse response, Func<string, bool>? include = null) =>
        string.Join("; ", response.Headers.SetCookie
            .Select(header => header![..header!.IndexOf(';')])
            .Where(pair => include?.Invoke(pair[..pair.IndexOf('=')]) ?? true));

    private sealed class ProductionEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "Aegis.Auth.Benchmarks";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
