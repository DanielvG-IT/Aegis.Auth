using Aegis.Auth.Entities;
using Aegis.Auth.Models;

namespace Aegis.Auth.Features.Sessions
{
    public class SessionCreateInput
    {
        public required User User { get; init; }
        public bool DontRememberMe { get; init; }
        public required string UserAgent { get; init; }
        public required string IpAddress { get; init; }
    }

    public class SessionDeleteInput
    {
        public required User User { get; init; }
        public required string Token { get; init; }
    }

    internal record SessionReference
    {
        public string Token { get; init; } = string.Empty; // The "Key" to the full cache
        public long ExpiresAt { get; init; } // When THIS specific session dies
    }

    internal record SessionCacheJson
    {
        public required SessionDto Session { get; init; }
        public required UserDto User { get; init; }
    }
}