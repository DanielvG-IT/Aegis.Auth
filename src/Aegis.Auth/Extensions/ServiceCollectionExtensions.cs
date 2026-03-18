using Aegis.Auth.Abstractions;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Features.SignOut;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Infrastructure.Auth;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAegisAuth<TContext>(
            this IServiceCollection services,
            Action<AegisAuthOptions>? configure = null)
            where TContext : class, IAuthDbContext
        {
            ArgumentNullException.ThrowIfNull(services);

            services.AddSingleton<IValidateOptions<AegisAuthOptions>, AegisAuthOptionsValidator>();
            services
                .AddOptions<AegisAuthOptions>()
                .Configure(configure ?? (_ => { }))
                .ValidateOnStart();

            // Backward compatibility for existing consumers resolving AegisAuthOptions directly.
            services.AddSingleton(sp => sp.GetRequiredService<IOptions<AegisAuthOptions>>().Value);

            // Register cookie handler
            services.AddScoped(sp =>
            {
                IHostEnvironment env = sp.GetRequiredService<IHostEnvironment>();
                AegisAuthOptions aegisOptions = sp.GetRequiredService<IOptions<AegisAuthOptions>>().Value;
                return new SessionCookieHandler(aegisOptions, env.IsDevelopment());
            });

            // Map the user's specific DB to your interface
            services.AddScoped<IAuthDbContext>(sp => sp.GetRequiredService<TContext>());

            // Add interfaced services
            services.AddScoped<ISessionService, SessionService>();
            services.AddScoped<ISignInService, SignInService>();
            services.AddScoped<ISignUpService, SignUpService>();
            services.AddScoped<ISignOutService, SignOutService>();
            services.AddScoped<IAegisAuthContextAccessor, AegisAuthContextAccessor>();

            return services;
        }

        private sealed class AegisAuthOptionsValidator : IValidateOptions<AegisAuthOptions>
        {
            public ValidateOptionsResult Validate(string? name, AegisAuthOptions options)
            {
                List<string> errors = [];

                if (string.IsNullOrWhiteSpace(options.AppName))
                {
                    errors.Add("AegisAuthOptions.AppName must be configured.");
                }

                if (string.IsNullOrWhiteSpace(options.BaseURL))
                {
                    errors.Add("AegisAuthOptions.BaseURL must be configured.");
                }
                else if (!Uri.TryCreate(options.BaseURL, UriKind.Absolute, out _))
                {
                    errors.Add("AegisAuthOptions.BaseURL must be a valid absolute URL.");
                }

                if (string.IsNullOrWhiteSpace(options.Secret) || options.Secret.Length < 32)
                {
                    errors.Add("AegisAuthOptions.Secret must be at least 32 characters long.");
                }

                if (options.EmailAndPassword.MinPasswordLength <= 0)
                {
                    errors.Add("AegisAuthOptions.EmailAndPassword.MinPasswordLength must be greater than 0.");
                }

                if (options.EmailAndPassword.MaxPasswordLength < options.EmailAndPassword.MinPasswordLength)
                {
                    errors.Add("AegisAuthOptions.EmailAndPassword.MaxPasswordLength must be greater than or equal to MinPasswordLength.");
                }

                if (options.Session.ExpiresIn < 0)
                {
                    errors.Add("AegisAuthOptions.Session.ExpiresIn cannot be negative.");
                }

                if (options.Session.CookieCache?.MaxAge is int maxAge && maxAge <= 0)
                {
                    errors.Add("AegisAuthOptions.Session.CookieCache.MaxAge must be greater than 0 when configured.");
                }

                if (options.TrustedOrigins is not null)
                {
                    foreach (var origin in options.TrustedOrigins)
                    {
                        if (!Uri.TryCreate(origin, UriKind.Absolute, out Uri? originUri)
                            || originUri.Scheme is not ("http" or "https"))
                        {
                            errors.Add("AegisAuthOptions.TrustedOrigins entries must be valid absolute http/https origins.");
                            break;
                        }
                    }
                }

                return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
            }
        }
    }
}
