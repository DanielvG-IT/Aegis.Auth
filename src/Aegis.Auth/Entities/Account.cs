using System.Text.Json.Serialization;

namespace Aegis.Auth.Entities
{
  /// <summary>
  /// Represents an account of a user
  /// </summary>
  public class Account
  {
    public string Id { get; set; } = string.Empty;
    public string AccountId { get; set; } = string.Empty;
    public string ProviderId { get; set; } = string.Empty;
    public string? AccessToken { get; set; } = null;
    public string? RefreshToken { get; set; } = null;
    public DateTime? AccessTokenExpiresAt { get; set; }
    public DateTime? RefreshTokenExpiresAt { get; set; }
    public string? Scope { get; set; } = null;
    public string? IdToken { get; set; } = null;
    public string? PasswordHash { get; set; } = null;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }


    // Relations
    public string UserId { get; set; } = string.Empty;
    [JsonIgnore]
    public User User { get; set; } = null!;
  }
}