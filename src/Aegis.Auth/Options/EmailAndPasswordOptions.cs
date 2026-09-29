using Aegis.Auth.Entities;

namespace Aegis.Auth.Options
{
    public sealed class EmailAndPasswordOptions
    {
        public bool Enabled { get; set; } = true;
        public PasswordOptions Password { get; set; } = new();
        public bool DisableSignUp { get; set; } = false;

        public bool AutoSignIn { get; set; } = true;

        /// <summary>
        /// When true, users with an unverified email cannot sign in with email and password,
        /// and sign-up does not auto sign in. Requires <see cref="EmailVerificationOptions.SendVerificationEmail"/>.
        /// </summary>
        public bool RequireEmailVerification { get; set; } = false;

        public int MinPasswordLength { get; set; } = 8;
        public int MaxPasswordLength { get; set; } = 128;

        /// <summary>
        /// Delivers the password reset token to the user (typically by email). The raw token is
        /// only ever passed to this delegate; it never appears in an HTTP response.
        /// Password reset endpoints are mapped only when this is configured.
        /// Prefer enqueuing the email over sending it inline: the delegate only runs for existing
        /// accounts, so a slow send makes response times reveal which emails are registered.
        /// </summary>
        public Func<SendResetPasswordContext, CancellationToken, Task>? SendResetPassword { get; set; }

        /// <summary>
        /// Lifetime of a password reset token in seconds. Defaults to 30 minutes.
        /// </summary>
        public int ResetPasswordTokenExpiresIn { get; set; } = 60 * 30;

        /// <summary>
        /// When true, all sessions of the user are revoked after a successful password reset.
        /// </summary>
        public bool RevokeSessionsOnPasswordReset { get; set; } = true;
    }

    public sealed class SendResetPasswordContext
    {
        public required User User { get; init; }

        /// <summary>
        /// The raw, single-use reset token. Build your reset link with it; never log it.
        /// </summary>
        public required string Token { get; init; }

        /// <summary>
        /// Request-scoped services, so the delegate can resolve your email sender.
        /// </summary>
        public required IServiceProvider Services { get; init; }
    }

    // TODO Maybe remove BCrypt dependency
    public sealed class PasswordOptions
    {
        public Func<string, Task<string>> Hash { get; set; } =
            password => Task.FromResult(BCrypt.Net.BCrypt.EnhancedHashPassword(password));

        public Func<PasswordVerifyContext, Task<bool>> Verify { get; set; } =
            ctx => Task.FromResult(BCrypt.Net.BCrypt.EnhancedVerify(ctx.Password, ctx.Hash));

        /// <summary>
        /// Custom password validation function for enforcing password requirements.
        /// Receives a PasswordValidateContext with the new password and optionally the old password.
        /// Return a PasswordValidationResult with success=true if valid, or success=false with error details if invalid.
        /// Use this to implement custom validation rules required by laws, business logic, etc.
        /// </summary>
        public Func<PasswordValidateContext, Task<PasswordValidationResult>>? Validate { get; set; }
    }

    public sealed class PasswordVerifyContext
    {
        public required string Hash { get; init; }
        public required string Password { get; init; }
    }

    public sealed class PasswordValidateContext
    {
        public required string Password { get; init; }
    }

    public sealed class PasswordValidationResult
    {
        public bool IsValid { get; internal set; }
        public string? ErrorMessage { get; internal set; }

        public static PasswordValidationResult Valid() => new() { IsValid = true };
        public static PasswordValidationResult Invalid(string errorMessage) =>
            new() { IsValid = false, ErrorMessage = errorMessage };
    }
}
