using Aegis.Auth.Abstractions;

namespace Aegis.Auth.Options
{
    public sealed class AuthOptions
    {
        public string AppName { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;

        public IAuthDbContext Database { get; set; } = default!;

        public EmailAndPasswordOptions EmailAndPassword { get; set; } = new();

    }

    public sealed class EmailAndPasswordOptions
    {
        public bool Enabled { get; set; } = true;
        public PasswordOptions Password { get; set; } = new();
        public bool DisableSignUp { get; set; } = false;
        public bool RequireEmailVerification { get; set; } = false;
        public bool AutoSignIn { get; set; } = true;

        public int MinPasswordLength { get; set; } = 8;
        public int MaxPasswordLength { get; set; } = 128;
    }

    public sealed class PasswordOptions
    {
        public Func<string, Task<string>> Hash { get; set; } =
            password => Task.FromResult(BCrypt.Net.BCrypt.EnhancedHashPassword(password));

        public Func<PasswordVerifyContext, Task<bool>> Verify { get; set; } =
            ctx => Task.FromResult(BCrypt.Net.BCrypt.EnhancedVerify(ctx.Password, ctx.Hash));
    }

    public sealed class PasswordVerifyContext
    {
        public required string Hash { get; init; }
        public required string Password { get; init; }
    }

    // ===== STORAGE HAHA! =======

    // public Func<ResetPasswordContext, HttpContext?, Task>?
    //     SendResetPassword
    // { get; set; }
    // public int ResetPasswordTokenExpiresIn { get; set; } = 3600;
    // public Func<User, HttpContext?, Task>? OnPasswordReset { get; set; }
    // public bool RevokeSessionsOnPasswordReset { get; set; }
    // public sealed class ResetPasswordContext
    // {
    //     public required User User { get; init; }
    //     public required string Url { get; init; }
    //     public required string Token { get; init; }
    // }
}
