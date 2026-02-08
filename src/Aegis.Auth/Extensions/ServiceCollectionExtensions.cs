using Microsoft.Extensions.DependencyInjection;

using Aegis.Auth.Options;
using Aegis.Auth.Services;

namespace Aegis.Auth.Extensions
{

  public static class ServiceCollectionExtensions
  {
    public static IServiceCollection AddAegisAuth(
        this IServiceCollection services,
        Action<AuthOptions>? configure = null)
    {
      var options = new AuthOptions();
      configure?.Invoke(options);

      services.AddSingleton(options);
      services.AddScoped<AuthService>();

      return services;
    }
  }
}