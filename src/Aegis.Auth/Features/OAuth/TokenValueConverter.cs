using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Aegis.Auth.Features.OAuth;

/// <summary>
/// EF Core value converter that automatically encrypts/decrypts tokens.
/// Applied at the database layer: plaintext in memory, encrypted in DB.
/// </summary>
internal sealed class TokenValueConverter : ValueConverter<string?, string?>
{
    public TokenValueConverter(ITokenEncryptionService encryptionService)
        : base(
            v => encryptionService.EncryptToken(v),
            v => encryptionService.DecryptToken(v),
            new ConverterMappingHints(size: 4000))
    {
    }
}
