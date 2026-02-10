using Aegis.Auth.Abstractions;
using Aegis.Auth.Options;

using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Extensions
{
  internal sealed class AegisAuthBuilder : IAegisAuthBuilder
  {
    public AegisAuthBuilder(IServiceCollection services, AegisAuthOptions options)
    {
      Services = services;
      Options = options;
    }

    public IServiceCollection Services { get; }
    public AegisAuthOptions Options { get; }
  }
}
