namespace Aegis.Auth.Models
{
    public class SessionCachePayload
    {
        public required long ExpiresAt { get; init; }
        public required string Signature { get; init; }
        public required SessionCacheDto Session { get; init; }
    }
    public class SessionCacheDto
    {
        public required SessionCacheMetadata Session { get; init; }
        public required long UpdatedAt { get; init; }
        public string Version { get; init; } = "1";
    }
    public class SessionCacheMetadata
    {
        public required UserDto User { get; init; }
        public required SessionDto Session { get; init; }
    }

    public class SessionDto
    {
        public required string Id { get; init; }
        public DateTime CreatedAt { get; init; }
        public DateTime UpdatedAt { get; init; }
        public required string Token { get; init; }
        public required string UserId { get; init; }
        public DateTime ExpiresAt { get; init; }
        public required string IpAddress { get; init; }
        public required string UserAgent { get; init; }
    }
}
