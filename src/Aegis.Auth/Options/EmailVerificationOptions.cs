using Aegis.Auth.Entities;

namespace Aegis.Auth.Options
{
    public sealed class EmailVerificationOptions
    {
        public int ExpiresIn { get; set; } = 60 * 15; // 15 min

        //* Send a verification email automatically after sign up.
        //* - `true`: Always send verification email on sign up
        //* - `false`: Never send verification email on sign up
        //* - `null`: Follows `requireEmailVerification` behavior
        public bool? SendOnSignIn { get; set; } = null;
        public bool SendOnSignUp { get; set; } = false;
        public bool AutoSignInAfterVerification { get; set; } = false;

        public Func<SendVerificationEmailContext, Task>? SendVerificationEmail { get; set; } = null;

        //Hooks
        // OnEmailVerification
        // BeforeEmailVerification
        // AfterEmailVerification
    }

    public sealed class SendVerificationEmailContext
    {
        public required User User { get; init; }
        public required string Url { get; init; }
        public required string Token { get; init; }
        public string? CallbackUri { get; init; }
    }
}