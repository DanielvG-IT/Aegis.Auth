using Aegis.Auth.Entities;
using Aegis.Auth.Models;

using System.Text.Json.Serialization;

namespace Aegis.Auth.Features.SignIn
{
    public class SignInEmailRequest
    {
        public required string Email { get; init; }
        public required string Password { get; init; }
        public string? Callback { get; init; }
        public bool RememberMe { get; init; } = true;
    }

    public class SignInEmailInput : SignInEmailRequest
    {
        public required string UserAgent { get; init; }
        public required string IpAddress { get; init; }
    }

    public class SignInResult
    {
        public required User User { get; init; } // The Entity
        public required Session Session { get; init; } // The Entity
        public required string? CallbackUrl { get; init; }
    }

    public class SignInResponse
    {
        public required UserDto User { get; init; }
        public required string Token { get; init; }
        public required bool Redirect { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; init; }
    }
}