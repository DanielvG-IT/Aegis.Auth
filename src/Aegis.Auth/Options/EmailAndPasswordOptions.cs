namespace Aegis.Auth.Options
{
    public sealed class EmailAndPasswordOptions
    {
        public bool Enabled { get; set; } = true;
        public PasswordOptions Password { get; set; } = new();
        public bool DisableSignUp { get; set; } = false;

        public bool AutoSignIn { get; set; } = true;

        // ═══════════════════════════════════════════════════════════════════════════════
        // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
        // ═══════════════════════════════════════════════════════════════════════════════
        // TODO v0.2: Uncomment these properties for email verification support
        // public bool RequireEmailVerification { get; set; } = false;
        // public Func<string, Task<string>>? SendVerificationEmail { get; set; }
        // ═══════════════════════════════════════════════════════════════════════════════

        public int MinPasswordLength { get; set; } = 8;
        public int MaxPasswordLength { get; set; } = 128;

        // public bool RevokeSessionsOnPasswordReset { get; set; }
        // public int ResetPasswordTokenExpiresIn { get; set; } = 3600;
        // public Func<ResetPasswordContext, Task>? SendResetPassword { get; set; }
        // public Func<User, HttpContext?, Task>? OnPasswordReset { get; set; }

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

    // public sealed class ResetPasswordContext
    // {
    //     public required User User { get; init; }
    //     public required string Url { get; init; }
    //     public required string Token { get; init; }
    // }
}