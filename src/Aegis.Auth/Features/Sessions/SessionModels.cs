using Aegis.Auth.Entities;

namespace Aegis.Auth.Features.Sessions
{
    public class SessionCreateInput
    {
        public required User User { get; init; }
        public bool DontRememberMe { get; init; }
        public required string UserAgent { get; init; }
        public required string IpAddress { get; init; }
    }

    internal record SessionReference
    {
        public string Token { get; set; } = string.Empty; // The "Key" to the full cache
        public long ExpiresAt { get; set; } // When THIS specific session dies
    }

    public record SessionCacheJson
    {
        public required Session Session { get; set; }
        public required User User { get; set; }
    }
}