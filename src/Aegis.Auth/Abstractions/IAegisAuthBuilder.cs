using Aegis.Auth.Options;

using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Abstractions
{
  /// <summary>
  /// Builder interface for configuring Aegis.Auth and its feature extensions.
  /// Enables fluent chaining of feature packages like .AddPasskeys(), .AddTotp(), etc.
  /// </summary>
  public interface IAegisAuthBuilder
  {
    /// <summary>
    /// The service collection to register feature services.
    /// </summary>
    IServiceCollection Services { get; }

    /// <summary>
    /// The core Aegis Auth options instance.
    /// Feature packages can extend this via nested properties.
    /// </summary>
    AegisAuthOptions Options { get; }
  }
}
