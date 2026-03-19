using System.Security.Claims;
using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Features.OAuth;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Features.SignIn;
using Aegis.Auth.Features.SignOut;
using Aegis.Auth.Features.SignUp;
using Aegis.Auth.Infrastructure.Auth;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

using AspNetOAuthOptions = Microsoft.AspNetCore.Authentication.OAuth.OAuthOptions;

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

            services.AddAuthentication()
                .AddCookie(AegisAuthSchemes.ExternalCookie)
                .AddGoogleIfConfigured();

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
            services.AddScoped<IOAuthService, OAuthService>();
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

                ValidateGoogleOptions(options, errors);

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

            private static void ValidateGoogleOptions(AegisAuthOptions options, List<string> errors)
            {
                if (options.OAuth.Enabled is false || options.OAuth.Google.Enabled is false)
                {
                    return;
                }

                if (string.IsNullOrWhiteSpace(options.OAuth.Google.ClientId))
                {
                    errors.Add("AegisAuthOptions.OAuth.Google.ClientId must be configured when Google OAuth is enabled.");
                }

                if (string.IsNullOrWhiteSpace(options.OAuth.Google.ClientSecret))
                {
                    errors.Add("AegisAuthOptions.OAuth.Google.ClientSecret must be configured when Google OAuth is enabled.");
                }

                if (!IsValidRelativePath(options.OAuth.Google.CallbackPath))
                {
                    errors.Add("AegisAuthOptions.OAuth.Google.CallbackPath must be an absolute path starting with '/'.");
                }

            }

            private static bool IsValidRelativePath(string path) =>
                string.IsNullOrWhiteSpace(path) is false && path.StartsWith('/');
        }

        private static AuthenticationBuilder AddGoogleIfConfigured(this AuthenticationBuilder authenticationBuilder)
        {
            authenticationBuilder.Services.AddSingleton<IConfigureOptions<AspNetOAuthOptions>, GoogleOAuthOptionsSetup>();
            authenticationBuilder.AddOAuth(AegisAuthSchemes.Google, _ => { });
            return authenticationBuilder;
        }

        private sealed class GoogleOAuthOptionsSetup(IOptions<AegisAuthOptions> aegisOptionsAccessor) : IConfigureNamedOptions<AspNetOAuthOptions>
        {
            private readonly AegisAuthOptions _aegisOptions = aegisOptionsAccessor.Value;

            public void Configure(AspNetOAuthOptions options) => Configure(Microsoft.Extensions.Options.Options.DefaultName, options);

            public void Configure(string? name, AspNetOAuthOptions options)
            {
                if (name != AegisAuthSchemes.Google)
                {
                    return;
                }

                var google = _aegisOptions.OAuth.Google;

                options.SignInScheme = AegisAuthSchemes.ExternalCookie;
                options.ClientId = google.ClientId;
                options.ClientSecret = google.ClientSecret;
                options.CallbackPath = google.CallbackPath;
                options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
                options.TokenEndpoint = "https://oauth2.googleapis.com/token";
                options.UserInformationEndpoint = "https://openidconnect.googleapis.com/v1/userinfo";
                options.SaveTokens = google.SaveTokens;
                options.Scope.Clear();

                foreach (var scope in google.Scopes.Where(scope => string.IsNullOrWhiteSpace(scope) is false))
                {
                    options.Scope.Add(scope);
                }

                options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
                options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
                options.ClaimActions.MapJsonKey("urn:google:picture", "picture");
                options.ClaimActions.MapJsonKey("urn:google:email_verified", "email_verified");

                options.Events = new OAuthEvents
                {
                    OnCreatingTicket = async context =>
                    {
                        using var response = await context.Backchannel.GetAsync(context.Options.UserInformationEndpoint, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        await using var payload = await response.Content.ReadAsStreamAsync(context.HttpContext.RequestAborted);
                        using var document = await JsonDocument.ParseAsync(payload, cancellationToken: context.HttpContext.RequestAborted);
                        context.RunClaimActions(document.RootElement);

                        if (document.RootElement.TryGetProperty("email_verified", out var emailVerifiedElement))
                        {
                            var emailVerified = emailVerifiedElement.ValueKind switch
                            {
                                JsonValueKind.True => "true",
                                JsonValueKind.False => "false",
                                JsonValueKind.String => emailVerifiedElement.GetString(),
                                _ => null,
                            };

                            if (string.IsNullOrWhiteSpace(emailVerified) is false)
                            {
                                context.Identity?.AddClaim(new Claim("urn:google:email_verified", emailVerified!));
                            }
                        }
                    }
                };
            }
        }
    }
}
