using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

using Aegis.Auth.Entities;
using Aegis.Auth.Models;

namespace Aegis.Auth.Features.SignUp
{
    public class SignUpEmailRequest
    {
        [Required]
        [StringLength(100, MinimumLength = 1)]
        public required string Name { get; init; }

        [Required]
        [EmailAddress]
        public required string Email { get; init; }

        [Required]
        [MinLength(1)]
        public required string Password { get; init; }

        [Url]
        public string? Image { get; init; }

        public string? Callback { get; init; }
    }

    public class SignUpEmailInput : SignUpEmailRequest
    {
        public required string UserAgent { get; init; }
        public required string IpAddress { get; init; }
    }

    public class SignUpResult
    {
        public required User User { get; init; }
        public required Session? Session { get; init; }
        public required string? CallbackUrl { get; init; }
    }

    public class SignUpResponse
    {
        public required UserDto User { get; init; }
        public required bool Redirect { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; init; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Token { get; init; }
    }
}
