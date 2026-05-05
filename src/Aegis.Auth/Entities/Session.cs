using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Aegis.Auth.Entities
{
    /// <summary>
    /// Represents a session of a user.
    /// Only the SHA-256 hash of the session token is persisted to the database.
    /// The raw token lives exclusively in the signed cookie; if the database leaks,
    /// stored hashes cannot be replayed directly.
    /// </summary>
    public class Session
    {
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// SHA-256 hex digest of the raw session token. Stored in the database.
        /// </summary>
        public string TokenHash { get; set; } = string.Empty;

        /// <summary>
        /// The raw (unhashed) session token. Set transiently after creation and used
        /// to populate the cookie. Never persisted to the database.
        /// </summary>
        [NotMapped]
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
