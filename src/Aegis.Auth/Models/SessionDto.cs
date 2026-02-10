namespace Aegis.Auth.Models
{
    public class SessionCachePayload
    {
        public required long ExpiresAt { get; set; }
        public required string Signature { get; set; }
        public required SessionCacheDto Session { get; set; }
    }
    public class SessionCacheDto
    {
        public required SessionCacheMetadata Session { get; set; }
        public required long UpdatedAt { get; set; }
        public string Version { get; set; } = "1";
    }
    public class SessionCacheMetadata
    {
        public required UserDto User { get; set; }
        public required SessionDto Session { get; set; }
    }

    public class SessionDto
    {
        public required string Id { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
        public required string Token { get; set; }
        public required string UserId { get; set; }
        public DateTime ExpiresAt { get; set; }
        public required string IpAddress { get; set; }
        public required string UserAgent { get; set; }
    }
}