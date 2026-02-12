using System.Text.Json.Serialization;

using Aegis.Auth.Entities;
using Aegis.Auth.Models;

namespace Aegis.Auth.Features.SignUp
{
    public class SignUpEmailRequest
    {
        public required string Name { get; init; }
        public required string Email { get; init; }
        public required string Password { get; init; }
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
        public Session? Session { get; init; }
        public string? CallbackUrl { get; init; }
    }

    public class SignUpResponse
    {
        public required UserDto User { get; set; }
        public string? Token { get; set; }
        public bool Redirect { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? Url { get; set; }
    }
}