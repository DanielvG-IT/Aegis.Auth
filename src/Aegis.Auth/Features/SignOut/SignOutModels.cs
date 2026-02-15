namespace Aegis.Auth.Features.SignOut
{
    public class SignOutInput
    {
        /// <summary>
        /// The raw session token extracted from the session cookie.
        /// </summary>
        public required string? Token { get; init; }
    }

    public class SignOutResponse
    {
        public required bool Success { get; init; }
    }
}