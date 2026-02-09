using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Features.SignUp;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Options;
using Aegis.Auth.Logging;

namespace Aegis.Auth.Extensions
{
  public static class ServiceCollectionExtensions
  {
    public static IServiceCollection AddAegisAuth<TContext>(
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

      // Add interfaced services
      services.AddScoped<ISignInService, SignInService>();
      services.AddScoped<ISignUpService, SignUpService>();

      return services;
    }
  }
}