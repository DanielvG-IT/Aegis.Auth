namespace Aegis.Auth.Passkeys
{
  /// <summary>
  /// Passkey credential entity - must be added to user's DbContext as DbSet&lt;PasskeyCredential&gt;.
  /// </summary>
  public class PasskeyCredential
  {
    public string Id { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty; // e.g., "iPhone 15", "MacBook Pro"
    public byte[] CredentialId { get; set; } = [];
    public byte[] PublicKey { get; set; } = [];
    public int SignCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
  }
}
