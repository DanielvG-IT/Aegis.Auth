using Aegis.Auth.Entities;
using Aegis.Auth.Models;

using System.Text.Json.Serialization;

namespace Aegis.Auth.Features.SignIn
{
    public class SignInEmailRequest
    {
        public string Email { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string? Callback { get; init; } = null;
        public bool RememberMe { get; init; } = false;
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
        public string? Url { get; set; } = null;
    }
}