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
        public required User User { get; set; } // The Entity
        public required Session Session { get; set; } // The Entity
        public string? CallbackUrl { get; set; }
    }

    public class SignInResponse
    {
        public required UserDto User { get; set; }
        public required string Token { get; set; }
        public bool Redirect { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; set; }
    }
}