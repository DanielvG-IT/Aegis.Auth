using Aegis.Auth.Abstractions;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Features.SignOut;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Infrastructure.Authentication;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

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
            services.AddScoped<ISignOutService, SignOutService>();

            return services;
        }

        public static IServiceCollection AddAegisAuthAuthentication(
            this IServiceCollection services,
            string authenticationScheme = AegisAuthenticationDefaults.AuthenticationScheme)
        {
            services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = authenticationScheme;
                    options.DefaultChallengeScheme = authenticationScheme;
                })
                .AddScheme<AuthenticationSchemeOptions, AegisAuthenticationHandler>(authenticationScheme, _ => { });

            services.AddAuthorization();
            return services;
        }
    }
}
