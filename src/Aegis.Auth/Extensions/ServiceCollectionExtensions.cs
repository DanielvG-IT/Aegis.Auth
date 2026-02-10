using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Features.SignUp;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Options;
using Aegis.Auth.Logging;
using Aegis.Auth.Core.Sessions;
using Aegis.Auth.Core.Security;
using Aegis.Auth.Infrastructure.Cookies;

namespace Aegis.Auth.Extensions
{
  public static class ServiceCollectionExtensions
  {
    public static IAegisAuthBuilder AddAegisAuth<TContext>(
        this IServiceCollection services,
        Action<AegisAuthOptions>? configure = null)
        where TContext : class, IAuthDbContext
    {
      var options = new AegisAuthOptions();
      configure?.Invoke(options);

      services.AddSingleton(options);
      services.TryAddSingleton<IAegisLogger, AegisLogger>();

      // Map the user's specific DB to your interface
      services.AddScoped<IAuthDbContext>(sp => sp.GetRequiredService<TContext>());

      // Add infrastructure services
      services.AddSingleton<TokenGenerator>();
      services.AddScoped<AegisCookieManager>();

      // Add shared services (used by core and feature packages)
      services.AddScoped<IAegisSessionService, AegisSessionService>();

      // Add core feature services
      services.AddScoped<ISignInService, SignInService>();
      services.AddScoped<ISignUpService, SignUpService>();

      return new AegisAuthBuilder(services, options);
    }
  }
}