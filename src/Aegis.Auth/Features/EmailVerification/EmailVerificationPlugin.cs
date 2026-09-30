using Aegis.Auth.Constants;
using Aegis.Auth.Options;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Features.EmailVerification;

/// <summary>
/// Email verification, built on the plugin contract. <c>AddAegisAuth</c> registers it for every app,
/// because sign-in and sign-up send verification emails. It is configured through
/// <see cref="AegisAuthOptions.EmailVerification"/>, and its endpoints are mapped once
/// <see cref="EmailVerificationOptions.SendVerificationEmail"/> is set.
/// </summary>
public sealed class EmailVerificationPlugin : AegisPlugin
{
    public const string PluginId = "email-verification";

    public override string Id => PluginId;

    public override void ConfigureServices(IServiceCollection services) =>
        services.AddScoped<IEmailVerificationService, EmailVerificationService>();

    public override void MapEndpoints(RouteGroupBuilder group) => group.MapEmailVerification();

    // Endpoints are only useful when the app can deliver the token.
    public override bool ShouldMapEndpoints(AegisAuthOptions options) =>
        options.EmailVerification.SendVerificationEmail is not null;

    public override IEnumerable<AegisRateLimitRule> RateLimitRules =>
    [
        new("/email-verify/send-token"),
        new("/email-verify/verify"),
    ];

    public override IReadOnlyDictionary<string, int> ErrorStatusCodes { get; } = new Dictionary<string, int>
    {
        [AuthErrors.System.VerificationEmailNotEnabled] = StatusCodes.Status403Forbidden,
    };

    public override void Validate(AegisAuthOptions options, IList<string> errors)
    {
        EmailVerificationOptions verification = options.EmailVerification;
        if (verification.SendVerificationEmail is null)
        {
            if (options.EmailAndPassword.RequireEmailVerification)
            {
                errors.Add("AegisAuthOptions.EmailVerification.SendVerificationEmail must be configured when EmailAndPassword.RequireEmailVerification is enabled.");
            }

            if (verification.SendOnSignUp is true || verification.SendOnSignIn is true)
            {
                errors.Add("AegisAuthOptions.EmailVerification.SendVerificationEmail must be configured when SendOnSignUp or SendOnSignIn is enabled.");
            }
        }

        if (verification.ExpiresIn <= 0)
        {
            errors.Add("AegisAuthOptions.EmailVerification.ExpiresIn must be greater than 0.");
        }
    }
}
