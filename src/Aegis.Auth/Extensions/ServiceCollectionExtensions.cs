using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Infrastructure.Cookies;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Options;

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

      // Register AegisCookieManager
      services.AddScoped(sp =>
      {
        IHostEnvironment env = sp.GetRequiredService<IHostEnvironment>();
        AegisAuthOptions aegisOptions = sp.GetRequiredService<AegisAuthOptions>();
        return new SessionCookieHandler(aegisOptions, env.IsDevelopment());
      });

      // Map the user's specific DB to your interface
      services.AddScoped<IAuthDbContext>(sp => sp.GetRequiredService<TContext>());

      // Add interfaced services
      services.AddScoped<ISessionService, SessionService>();
      services.AddScoped<ISignInService, SignInService>();
      services.AddScoped<ISignUpService, SignUpService>();

      return services;
    }
  }
}