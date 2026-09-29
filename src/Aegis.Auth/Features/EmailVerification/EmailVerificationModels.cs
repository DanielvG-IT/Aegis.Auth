namespace Aegis.Auth.Features.EmailVerification;

public class SendVerificationTokenRequest
{
    /// <summary>
    /// Required when the caller has no session (e.g. sign-in was blocked for an unverified email).
    /// Ignored when the caller is signed in; the session's user is used instead.
    /// </summary>
    public string? Email { get; set; }
}

public class VerifyEmailRequest
{
    public string Token { get; set; } = string.Empty;
}
