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
    public User User { get; set; } = null!;
  }
}