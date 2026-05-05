using System.Text.Json.Serialization;

namespace Aegis.Auth.Entities;

/// <summary>
/// Represents a time-limited token for email verification or password reset.
/// Only the SHA-256 hash of the raw token is stored in the database.
/// The raw token is sent to the user via email and never persisted.
/// </summary>
public class AuthToken
{
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 hex digest of the raw token. Stored in the database only.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Purpose of this token: "email-verification", "password-reset", etc.
    /// </summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>
    /// When this token expires. Tokens are single-use: after validation, ConsumedAt is set to prevent reuse.
    /// </summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// When this token was consumed (used successfully). Null if not yet used.
    /// Tokens can only be used once.
    /// </summary>
    public DateTime? ConsumedAt { get; set; }

    public DateTime CreatedAt { get; set; }

    // Relations
    public string UserId { get; set; } = string.Empty;

    [JsonIgnore]
    public User User { get; set; } = null!;
}
