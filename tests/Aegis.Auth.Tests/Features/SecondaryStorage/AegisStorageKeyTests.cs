using Aegis.Auth.Features.SecondaryStorage;

namespace Aegis.Auth.Tests.Features.SecondaryStorage;

public sealed class AegisStorageKeyTests
{
    [Fact]
    public void Create_BuildsNamespacedKey()
    {
        Assert.Equal("aegis:passkey:challenge:abc", AegisStorageKey.Create("passkey", "challenge", "abc"));
    }

    [Fact]
    public void Create_AllowsSeparatorInId()
    {
        Assert.Equal("aegis:sso:request:a:b", AegisStorageKey.Create("sso", "request", "a:b"));
    }

    [Theory]
    [InlineData("", "purpose", "id")]
    [InlineData("plugin", "", "id")]
    [InlineData("plugin", "purpose", "")]
    [InlineData("plug:in", "purpose", "id")]
    [InlineData("plugin", "pur:pose", "id")]
    public void Create_InvalidSegment_Throws(string pluginId, string purpose, string id)
    {
        Assert.ThrowsAny<ArgumentException>(() => AegisStorageKey.Create(pluginId, purpose, id));
    }

    [Fact]
    public void Create_TooLong_Throws()
    {
        Assert.Throws<ArgumentException>(() => AegisStorageKey.Create("plugin", "purpose", new string('x', AegisStorageKey.MaxLength)));
    }
}
