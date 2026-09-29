using Aegis.Auth.Entities;

namespace Aegis.Auth.Options
{
    public sealed class EmailVerificationOptions
    {
        /// <summary>
        /// Lifetime of an email verification token in seconds. Defaults to 15 minutes.
        /// </summary>
        public int ExpiresIn { get; set; } = 60 * 15;

        /// <summary>
        /// Send a verification email when an unverified user signs in.
        /// - <c>true</c>: always send (only applies while sign-in is blocked by RequireEmailVerification)
        /// - <c>false</c>: never send
        /// - <c>null</c>: follows <see cref="EmailAndPasswordOptions.RequireEmailVerification"/>
        /// </summary>
        public bool? SendOnSignIn { get; set; } = null;

        /// <summary>
        /// Send a verification email after sign-up.
        /// - <c>true</c>: always send
        /// - <c>false</c>: never send
        /// - <c>null</c>: follows <see cref="EmailAndPasswordOptions.RequireEmailVerification"/>
        /// </summary>
        public bool? SendOnSignUp { get; set; } = null;

        /// <summary>
        /// Delivers the verification token to the user (typically by email). The raw token is
        /// only ever passed to this delegate; it never appears in an HTTP response.
        /// Email verification endpoints are mapped only when this is configured.
        /// Prefer enqueuing the email over sending it inline: the delegate only runs for existing
        /// accounts, so a slow send makes response times reveal which emails are registered.
        /// </summary>
        public Func<SendVerificationEmailContext, CancellationToken, Task>? SendVerificationEmail { get; set; }
    }

    public sealed class SendVerificationEmailContext
    {
        public required User User { get; init; }

        /// <summary>
        /// The raw, single-use verification token. Build your verification link with it; never log it.
        /// </summary>
        public required string Token { get; init; }

        /// <summary>
        /// Request-scoped services, so the delegate can resolve your email sender.
        /// </summary>
        public required IServiceProvider Services { get; init; }
    }
}
