using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
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
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
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
                .AddExternalOAuthProviders();

            // Backward compatibility for existing consumers resolving AegisAuthOptions directly.
            services.AddSingleton(sp => sp.GetRequiredService<IOptions<AegisAuthOptions>>().Value);

            services.AddScoped(sp =>
            {
                IHostEnvironment env = sp.GetRequiredService<IHostEnvironment>();
                AegisAuthOptions aegisOptions = sp.GetRequiredService<IOptions<AegisAuthOptions>>().Value;
                return new SessionCookieHandler(aegisOptions, env.IsDevelopment());
            });

            services.AddScoped<IAuthDbContext>(sp => sp.GetRequiredService<TContext>());

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

                ValidateOAuthProviderOptions(options, errors);

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

            private static void ValidateOAuthProviderOptions(AegisAuthOptions options, List<string> errors)
            {
                if (options.OAuth.Enabled is false)
                {
                    return;
                }

                foreach (OAuthProviderDefinition provider in OAuthProviderCatalog.All)
                {
                    OAuthProviderOptions providerOptions = provider.GetOptions(options.OAuth);
                    if (providerOptions.Enabled is false)
                    {
                        continue;
                    }

                    var optionPath = $"AegisAuthOptions.OAuth.{provider.OptionName}";

                    if (string.IsNullOrWhiteSpace(providerOptions.ClientId))
                    {
                        errors.Add($"{optionPath}.ClientId must be configured when {provider.DisplayName} OAuth is enabled.");
                    }

                    if (string.IsNullOrWhiteSpace(providerOptions.ClientSecret))
                    {
                        errors.Add($"{optionPath}.ClientSecret must be configured when {provider.DisplayName} OAuth is enabled.");
                    }

                    if (!IsValidRelativePath(providerOptions.CallbackPath))
                    {
                        errors.Add($"{optionPath}.CallbackPath must be an absolute path starting with '/'.");
                    }
                }

                if (options.OAuth.Microsoft.Enabled && string.IsNullOrWhiteSpace(options.OAuth.Microsoft.TenantId))
                {
                    errors.Add("AegisAuthOptions.OAuth.Microsoft.TenantId must be configured when Microsoft OAuth is enabled.");
                }

                if (options.OAuth.Apple.Enabled
                    && IsSupportedAppleResponseMode(options.OAuth.Apple.ResponseMode) is false)
                {
                    errors.Add("AegisAuthOptions.OAuth.Apple.ResponseMode must be one of: query, fragment, form_post.");
                }
            }

            private static bool IsValidRelativePath(string path) =>
                string.IsNullOrWhiteSpace(path) is false && path.StartsWith('/');

            private static bool IsSupportedAppleResponseMode(string? responseMode) =>
                string.Equals(responseMode, "query", StringComparison.OrdinalIgnoreCase)
                || string.Equals(responseMode, "fragment", StringComparison.OrdinalIgnoreCase)
                || string.Equals(responseMode, "form_post", StringComparison.OrdinalIgnoreCase);
        }

        private static AuthenticationBuilder AddExternalOAuthProviders(this AuthenticationBuilder authenticationBuilder)
        {
            authenticationBuilder.Services.AddSingleton<IConfigureOptions<AspNetOAuthOptions>, ExternalOAuthOptionsSetup>();
            authenticationBuilder.AddOAuth(AegisAuthSchemes.Google, _ => { });
            authenticationBuilder.AddOAuth(AegisAuthSchemes.GitHub, _ => { });
            authenticationBuilder.AddOAuth(AegisAuthSchemes.Microsoft, _ => { });
            authenticationBuilder.AddOAuth(AegisAuthSchemes.Apple, _ => { });
            return authenticationBuilder;
        }

        private sealed class ExternalOAuthOptionsSetup(IOptions<AegisAuthOptions> aegisOptionsAccessor) : IConfigureNamedOptions<AspNetOAuthOptions>
        {
            private readonly AegisAuthOptions _aegisOptions = aegisOptionsAccessor.Value;

            public void Configure(AspNetOAuthOptions options) => Configure(Microsoft.Extensions.Options.Options.DefaultName, options);

            public void Configure(string? name, AspNetOAuthOptions options)
            {
                switch (name)
                {
                    case AegisAuthSchemes.Google:
                        ConfigureGoogle(options, _aegisOptions.OAuth.Google);
                        break;
                    case AegisAuthSchemes.GitHub:
                        ConfigureGitHub(options, _aegisOptions.OAuth.GitHub);
                        break;
                    case AegisAuthSchemes.Microsoft:
                        ConfigureMicrosoft(options, _aegisOptions.OAuth.Microsoft);
                        break;
                    case AegisAuthSchemes.Apple:
                        ConfigureApple(options, _aegisOptions.OAuth.Apple);
                        break;
                }
            }
        }

        private static void ConfigureGoogle(AspNetOAuthOptions options, GoogleOAuthOptions google)
        {
            ConfigureCommonProvider(options, google);

            options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
            options.TokenEndpoint = "https://oauth2.googleapis.com/token";
            options.UserInformationEndpoint = "https://openidconnect.googleapis.com/v1/userinfo";

            options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            options.ClaimActions.MapJsonKey("urn:google:picture", "picture");

            options.Events = new OAuthEvents
            {
                OnCreatingTicket = async context =>
                {
                    AddIdTokenClaimFromTokenResponse(context);

                    using JsonDocument document = await GetUserInfoDocumentAsync(context, context.Options.UserInformationEndpoint);
                    context.RunClaimActions(document.RootElement);
                    SetClaim(context.Identity, "urn:google:email_verified", GetJsonBooleanString(document.RootElement, "email_verified"));
                }
            };
        }

        private static void ConfigureGitHub(AspNetOAuthOptions options, GitHubOAuthOptions gitHub)
        {
            ConfigureCommonProvider(options, gitHub);

            options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
            options.TokenEndpoint = "https://github.com/login/oauth/access_token";
            options.UserInformationEndpoint = "https://api.github.com/user";

            options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
            options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            options.ClaimActions.MapJsonKey("urn:github:login", "login");
            options.ClaimActions.MapJsonKey("urn:github:avatar_url", "avatar_url");

            options.Events = new OAuthEvents
            {
                OnCreatingTicket = async context =>
                {
                    using JsonDocument document = await GetUserInfoDocumentAsync(context, context.Options.UserInformationEndpoint, ConfigureGitHubApiRequest);
                    context.RunClaimActions(document.RootElement);

                    var login = GetJsonString(document.RootElement, "login");
                    if (string.IsNullOrWhiteSpace(GetJsonString(document.RootElement, "name")) && string.IsNullOrWhiteSpace(login) is false)
                    {
                        SetClaim(context.Identity, ClaimTypes.Name, login);
                    }

                    GitHubEmailSelection? emailSelection = await TryGetGitHubEmailAsync(context);
                    if (emailSelection is not null)
                    {
                        SetClaim(context.Identity, ClaimTypes.Email, emailSelection.Email);
                        SetClaim(context.Identity, "urn:github:email_verified", emailSelection.Verified ? bool.TrueString : bool.FalseString);
                    }
                }
            };
        }

        private static void ConfigureMicrosoft(AspNetOAuthOptions options, MicrosoftOAuthOptions microsoft)
        {
            ConfigureCommonProvider(options, microsoft);

            var tenantId = Uri.EscapeDataString(microsoft.TenantId);
            options.AuthorizationEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize";
            options.TokenEndpoint = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";
            options.UserInformationEndpoint = "https://graph.microsoft.com/oidc/userinfo";

            options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            options.ClaimActions.MapJsonKey("preferred_username", "preferred_username");

            options.Events = new OAuthEvents
            {
                OnCreatingTicket = async context =>
                {
                    AddIdTokenClaimFromTokenResponse(context);

                    using JsonDocument document = await GetUserInfoDocumentAsync(context, context.Options.UserInformationEndpoint);
                    context.RunClaimActions(document.RootElement);
                }
            };
        }

        private static void ConfigureApple(AspNetOAuthOptions options, AppleOAuthOptions apple)
        {
            ConfigureCommonProvider(options, apple);

            options.AuthorizationEndpoint = "https://appleid.apple.com/auth/authorize";
            options.TokenEndpoint = "https://appleid.apple.com/auth/token";

            options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            options.ClaimActions.MapJsonKey("urn:apple:email_verified", "email_verified");

            options.Events = new OAuthEvents
            {
                OnRedirectToAuthorizationEndpoint = context =>
                {
                    var redirectUri = QueryHelpers.AddQueryString(
                        context.RedirectUri,
                        "response_mode",
                        apple.ResponseMode);

                    context.Response.Redirect(redirectUri);
                    return Task.CompletedTask;
                },
                OnCreatingTicket = async context =>
                {
                    AddIdTokenClaimFromTokenResponse(context);

                    JsonDocument? tokenResponse = context.TokenResponse.Response;
                    if (tokenResponse is not null
                        && TryGetJsonString(tokenResponse.RootElement, "id_token", out var idToken)
                        && TryReadJwtPayload(idToken!, out JsonDocument? payloadDocument)
                        && payloadDocument is not null)
                    {
                        using (payloadDocument)
                        {
                            context.RunClaimActions(payloadDocument.RootElement);
                        }
                    }

                    using JsonDocument? appleUserDocument = await TryReadAppleUserPayloadAsync(context);
                    if (appleUserDocument is null)
                    {
                        return;
                    }

                    var email = GetJsonString(appleUserDocument.RootElement, "email");
                    if (string.IsNullOrWhiteSpace(email) is false)
                    {
                        SetClaim(context.Identity, ClaimTypes.Email, email);
                        SetClaim(context.Identity, "urn:apple:email", email);
                    }

                    var fullName = BuildAppleFullName(appleUserDocument.RootElement);
                    if (string.IsNullOrWhiteSpace(fullName) is false)
                    {
                        SetClaim(context.Identity, ClaimTypes.Name, fullName);
                        SetClaim(context.Identity, "urn:apple:name", fullName);
                    }
                }
            };
        }

        private static void ConfigureCommonProvider(AspNetOAuthOptions options, OAuthProviderOptions providerOptions)
        {
            options.SignInScheme = AegisAuthSchemes.ExternalCookie;
            options.ClientId = providerOptions.ClientId;
            options.ClientSecret = providerOptions.ClientSecret;
            options.CallbackPath = providerOptions.CallbackPath;
            options.SaveTokens = providerOptions.SaveTokens;
            options.UsePkce = true;
            options.Scope.Clear();
            options.ClaimActions.Clear();

            foreach (var scope in providerOptions.Scopes.Where(scope => string.IsNullOrWhiteSpace(scope) is false))
            {
                options.Scope.Add(scope);
            }
        }

        private static async Task<JsonDocument> GetUserInfoDocumentAsync(
            OAuthCreatingTicketContext context,
            string endpoint,
            Action<HttpRequestMessage>? configureRequest = null)
        {
            if (string.IsNullOrWhiteSpace(context.AccessToken))
            {
                throw new InvalidOperationException("The OAuth provider did not return an access token.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            configureRequest?.Invoke(request);

            using HttpResponseMessage response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
            response.EnsureSuccessStatusCode();

            await using var payload = await response.Content.ReadAsStreamAsync(context.HttpContext.RequestAborted);
            return await JsonDocument.ParseAsync(payload, cancellationToken: context.HttpContext.RequestAborted);
        }

        private static void ConfigureGitHubApiRequest(HttpRequestMessage request)
        {
            request.Headers.Accept.Clear();
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            request.Headers.UserAgent.ParseAdd("Aegis.Auth");
            request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        }

        private static async Task<GitHubEmailSelection?> TryGetGitHubEmailAsync(OAuthCreatingTicketContext context)
        {
            if (string.IsNullOrWhiteSpace(context.AccessToken))
            {
                return null;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
            ConfigureGitHubApiRequest(request);

            using HttpResponseMessage response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var payload = await response.Content.ReadAsStreamAsync(context.HttpContext.RequestAborted);
            using JsonDocument document = await JsonDocument.ParseAsync(payload, cancellationToken: context.HttpContext.RequestAborted);

            return SelectGitHubEmail(document.RootElement);
        }

        private static GitHubEmailSelection? SelectGitHubEmail(JsonElement root)
        {
            if (root.ValueKind is not JsonValueKind.Array)
            {
                return null;
            }

            GitHubEmailSelection? best = null;

            foreach (JsonElement item in root.EnumerateArray())
            {
                var email = GetJsonString(item, "email");
                if (string.IsNullOrWhiteSpace(email))
                {
                    continue;
                }

                var isPrimary = GetJsonBoolean(item, "primary");
                var isVerified = GetJsonBoolean(item, "verified");

                if (isPrimary && isVerified)
                {
                    return new GitHubEmailSelection(email, true);
                }

                if (best is null || (isVerified && best.Verified is false))
                {
                    best = new GitHubEmailSelection(email, isVerified);
                }
            }

            return best;
        }

        private static void AddIdTokenClaimFromTokenResponse(OAuthCreatingTicketContext context)
        {
            JsonDocument? tokenResponse = context.TokenResponse.Response;
            if (tokenResponse is not null
                && TryGetJsonString(tokenResponse.RootElement, "id_token", out var idToken))
            {
                SetClaim(context.Identity, "urn:aegis:id_token", idToken);
            }
        }

        private static void SetClaim(ClaimsIdentity? identity, string claimType, string? value)
        {
            if (identity is null || string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            foreach (Claim existingClaim in identity.FindAll(claimType).ToList())
            {
                identity.RemoveClaim(existingClaim);
            }

            identity.AddClaim(new Claim(claimType, value));
        }

        private static bool TryReadJwtPayload(string token, out JsonDocument? payloadDocument)
        {
            payloadDocument = null;

            var parts = token.Split('.');
            if (parts.Length < 2 || string.IsNullOrWhiteSpace(parts[1]))
            {
                return false;
            }

            try
            {
                var bytes = DecodeBase64Url(parts[1]);
                payloadDocument = JsonDocument.Parse(bytes);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        private static async Task<JsonDocument?> TryReadAppleUserPayloadAsync(OAuthCreatingTicketContext context)
        {
            string? userPayload = null;

            if (context.Request.HasFormContentType)
            {
                IFormCollection form = await context.Request.ReadFormAsync(context.HttpContext.RequestAborted);
                userPayload = form["user"].ToString();
            }

            if (string.IsNullOrWhiteSpace(userPayload) && context.Request.Query.TryGetValue("user", out var queryValue))
            {
                userPayload = queryValue.ToString();
            }

            if (string.IsNullOrWhiteSpace(userPayload))
            {
                return null;
            }

            try
            {
                return JsonDocument.Parse(userPayload);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static string? BuildAppleFullName(JsonElement root)
        {
            if (!root.TryGetProperty("name", out JsonElement nameElement) || nameElement.ValueKind is not JsonValueKind.Object)
            {
                return null;
            }

            var firstName = GetJsonString(nameElement, "firstName") ?? GetJsonString(nameElement, "first_name");
            var lastName = GetJsonString(nameElement, "lastName") ?? GetJsonString(nameElement, "last_name");

            var fullName = string.Join(" ", new[] { firstName, lastName }.Where(part => string.IsNullOrWhiteSpace(part) is false)).Trim();
            return string.IsNullOrWhiteSpace(fullName) ? null : fullName;
        }

        private static string? GetJsonString(JsonElement element, string propertyName)
        {
            if (!element.TryGetProperty(propertyName, out JsonElement property))
            {
                return null;
            }

            return property.ValueKind switch
            {
                JsonValueKind.String => property.GetString(),
                JsonValueKind.Number => property.GetRawText(),
                JsonValueKind.True => bool.TrueString,
                JsonValueKind.False => bool.FalseString,
                _ => null,
            };
        }

        private static string? GetJsonBooleanString(JsonElement element, string propertyName)
        {
            if (!element.TryGetProperty(propertyName, out JsonElement property))
            {
                return null;
            }

            return property.ValueKind switch
            {
                JsonValueKind.True => bool.TrueString,
                JsonValueKind.False => bool.FalseString,
                JsonValueKind.String => property.GetString(),
                _ => null,
            };
        }

        private static bool GetJsonBoolean(JsonElement element, string propertyName)
        {
            if (!element.TryGetProperty(propertyName, out JsonElement property))
            {
                return false;
            }

            return property.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.String when bool.TryParse(property.GetString(), out var parsed) => parsed,
                _ => false,
            };
        }

        private static bool TryGetJsonString(JsonElement element, string propertyName, out string? value)
        {
            value = GetJsonString(element, propertyName);
            return string.IsNullOrWhiteSpace(value) is false;
        }

        private static byte[] DecodeBase64Url(string input)
        {
            var normalized = input.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
            return Convert.FromBase64String(normalized);
        }

        private sealed record GitHubEmailSelection(string Email, bool Verified);
    }
}
