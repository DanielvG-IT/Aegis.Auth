using Aegis.Auth.Abstractions;
using Aegis.Auth.Passkeys.Abstractions;
using Aegis.Auth.Passkeys.Options;

namespace Aegis.Auth.Passkeys.Extensions
{
  /// <summary>
  /// Extension methods for adding Passkey authentication to Aegis.Auth.
  /// </summary>
  public static class PasskeyExtensions
  {
    /// <summary>
    /// Adds Passkey (WebAuthn) authentication support.
    /// 
    /// Usage:
    /// <code>
    /// builder.Services.AddAegisAuth&lt;AppDbContext&gt;(options => { ... })
    ///     .AddPasskeys(passkey => 
    ///     {
    ///         passkey.RelyingPartyName = "My App";
    ///         passkey.RelyingPartyId = "example.com";
    ///     });
    /// </code>
    /// 
    /// Consumer must add PasskeyCredential entity to their DbContext:
    /// <code>
    /// public DbSet&lt;PasskeyCredential&gt; PasskeyCredentials => Set&lt;PasskeyCredential&gt;();
    /// </code>
    /// </summary>
    public static IAegisAuthBuilder AddPasskeys(
        this IAegisAuthBuilder builder,
        Action<PasskeyOptions>? configure = null)
    {
      var options = new PasskeyOptions
      {
        // Defaults from core options if available
        RelyingPartyName = builder.Options.AppName,
        RelyingPartyId = ExtractDomain(builder.Options.BaseURL)
      };

      configure?.Invoke(options);

      // Validate required options
      if (string.IsNullOrWhiteSpace(options.RelyingPartyName))
        throw new ArgumentException("PasskeyOptions.RelyingPartyName is required");
      if (string.IsNullOrWhiteSpace(options.RelyingPartyId))
        throw new ArgumentException("PasskeyOptions.RelyingPartyId is required");

      // Register services
      builder.Services.AddSingleton(options);
      builder.Services.AddScoped<IPasskeyService, PasskeyService>();

      return builder;
    }

    private static string ExtractDomain(string url)
    {
      if (string.IsNullOrWhiteSpace(url)) return string.Empty;
      if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return uri.Host;
      return url;
    }
  }
}
