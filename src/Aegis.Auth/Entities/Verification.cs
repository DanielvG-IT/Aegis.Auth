namespace Aegis.Auth.Entities
{
  /// <summary>
  /// Represents something 
  /// </summary>
  public class Verification
  {
    public string Id { get; set; } = string.Empty;
    public string Identifier { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
  }
}