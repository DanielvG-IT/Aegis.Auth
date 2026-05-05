namespace Aegis.Auth.Features.OAuth;

/// <summary>
/// Encrypts and decrypts OAuth tokens using ASP.NET Core Data Protection API.
/// Tokens are encrypted at rest in the database and decrypted on retrieval.
/// </summary>
public interface ITokenEncryptionService
{
    string EncryptToken(string? plaintext);
    string? DecryptToken(string? ciphertext);
}
