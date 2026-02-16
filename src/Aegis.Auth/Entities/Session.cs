using System.Text.Json.Serialization;

namespace Aegis.Auth.Entities
{
    /// <summary>
    /// Represents a session of a user
    /// </summary>
    public class Session
    {
        public string Id { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public string IpAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }

        // Relations
        public string UserId { get; set; } = string.Empty;

        /// <summary>
        /// Navigation property to the User entity. May not be populated in all scenarios
        /// to avoid EF Core tracking conflicts. Use UserId and query separately when needed.
        /// </summary>
        [JsonIgnore]
        public User User { get; set; } = null!;
    }
}