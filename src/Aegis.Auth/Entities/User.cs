namespace Aegis.Auth.Entities
{
  /// <summary>
  /// Represents a user
  /// </summary>
  public class User
  {
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailVerified { get; set; } = false;
    public string? Image { get; set; } = null;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    // Relations
    public ICollection<Account> Accounts { get; } = [];
    public ICollection<Session> Sessions { get; } = [];
  }
}