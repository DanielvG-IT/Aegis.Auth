using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Aegis.Auth.Entities;
using Aegis.Auth.Models;

namespace Aegis.Auth.Features.SignIn
{
    public class SignInEmailRequest
    {
        [Required]
        [EmailAddress]
        public required string Email { get; init; }

        [Required]
        [MinLength(1)]
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
        public required bool Redirect { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; init; }

        /// <summary>
        /// Only populated when the client sends X-Aegis-Token-Response: true.
        /// Intended for mobile/API clients that cannot use HttpOnly cookies.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Token { get; init; }
    }
}
