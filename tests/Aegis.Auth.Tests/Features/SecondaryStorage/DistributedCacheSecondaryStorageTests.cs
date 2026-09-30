using Aegis.Auth.Features.SecondaryStorage;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;

namespace Aegis.Auth.Tests.Features.SecondaryStorage;

public sealed class DistributedCacheSecondaryStorageTests : SecondaryStorageContractTests
{
    private const string NotAtomic =
        "IDistributedCache has no compare-and-set or increment, so this adapter is documented as non-atomic (startup warning, event 9000).";

    private readonly MemoryDistributedCache _cache = new(Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions()));

    protected override IAegisSecondaryStorage CreateStorage(TimeProvider timeProvider) =>
        new DistributedCacheSecondaryStorage(_cache, timeProvider);

    [Fact(Skip = NotAtomic)]
    public override Task SetIfNotExists_ParallelCallers_ExactlyOneWins() => Task.CompletedTask;

    [Fact(Skip = NotAtomic)]
    public override Task Increment_ParallelCallers_NoIncrementIsLost() => Task.CompletedTask;


    [Fact]
    public async Task Get_ValueNotWrittenByAdapter_IsTreatedAsMissing()
    {
        await _cache.SetStringAsync("foreign", "plain value");

        Assert.Null(await Storage.GetAsync("foreign"));
    }

    [Fact]
    public async Task Set_StoresValueWithEmbeddedExpiry()
    {
        await Storage.SetAsync("key", "a:b", TimeSpan.FromMinutes(1));

        var raw = await _cache.GetStringAsync("key");
        Assert.Equal($"{Clock.GetUtcNow().AddMinutes(1).UtcTicks}:a:b", raw);
        Assert.Equal("a:b", await Storage.GetAsync("key"));
    }
}
