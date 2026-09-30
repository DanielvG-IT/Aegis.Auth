using Aegis.Auth.Features.SecondaryStorage;

using Microsoft.Extensions.Logging.Abstractions;

namespace Aegis.Auth.Tests.Features.SecondaryStorage;

public sealed class InMemorySecondaryStorageTests : SecondaryStorageContractTests
{
    protected override IAegisSecondaryStorage CreateStorage(TimeProvider timeProvider) =>
        new InMemorySecondaryStorage(timeProvider, NullLoggerFactory.Instance);

    [Fact]
    public async Task Write_AfterSweepInterval_EvictsExpiredEntries()
    {
        var sut = (InMemorySecondaryStorage)Storage;
        await sut.SetAsync("expired-1", "v", TimeSpan.FromSeconds(1));
        await sut.SetAsync("expired-2", "v", TimeSpan.FromSeconds(1));
        await sut.SetAsync("alive", "v", TimeSpan.FromHours(1));
        Assert.Equal(3, sut.Count);

        Clock.Advance(InMemorySecondaryStorage.SweepInterval);
        await sut.SetAsync("trigger", "v", TimeSpan.FromHours(1));

        Assert.Equal(2, sut.Count);
        Assert.Equal("v", await sut.GetAsync("alive"));
    }

    [Fact]
    public async Task Write_BeforeSweepInterval_DoesNotSweep()
    {
        var sut = (InMemorySecondaryStorage)Storage;
        await sut.SetAsync("expired", "v", TimeSpan.FromSeconds(1));

        Clock.Advance(TimeSpan.FromSeconds(2));
        await sut.SetAsync("trigger", "v", TimeSpan.FromHours(1));

        // Still stored (the sweep is not due yet) but already invisible.
        Assert.Equal(2, sut.Count);
        Assert.Null(await sut.GetAsync("expired"));
    }
}
