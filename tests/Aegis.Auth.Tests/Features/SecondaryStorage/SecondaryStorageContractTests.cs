using Aegis.Auth.Features.SecondaryStorage;
using Aegis.Auth.Tests.Helpers;

using Microsoft.Extensions.Time.Testing;

namespace Aegis.Auth.Tests.Features.SecondaryStorage;

/// <summary>
/// Behaviour every <see cref="IAegisSecondaryStorage"/> implementation must share. Each implementation
/// gets a derived class; implementations that cannot meet a guarantee override the test with a skip reason.
/// </summary>
public abstract class SecondaryStorageContractTests
{
    protected const int ParallelCallers = 50;

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(1);

    private IAegisSecondaryStorage? _storage;

    private protected FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    protected IAegisSecondaryStorage Storage => _storage ??= CreateStorage(Clock);

    protected abstract IAegisSecondaryStorage CreateStorage(TimeProvider timeProvider);

    private static string NewKey() => AegisStorageKey.Create("test", "contract", Guid.NewGuid().ToString("N"));

    // ═══════════════════════════════════════════════════════════════════════════
    // GET / SET
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Get_MissingKey_ReturnsNull()
    {
        Assert.Null(await Storage.GetAsync(NewKey()));
    }

    [Fact]
    public async Task Set_ThenGet_ReturnsValue()
    {
        var key = NewKey();

        await Storage.SetAsync(key, "value", Ttl);

        Assert.Equal("value", await Storage.GetAsync(key));
    }

    [Fact]
    public async Task Set_ExistingKey_ReplacesValueAndExpiry()
    {
        var key = NewKey();
        await Storage.SetAsync(key, "first", TimeSpan.FromSeconds(10));

        await Storage.SetAsync(key, "second", TimeSpan.FromMinutes(5));
        Clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal("second", await Storage.GetAsync(key));
    }

    [Fact]
    public async Task Get_AfterTtl_ReturnsNull()
    {
        var key = NewKey();
        await Storage.SetAsync(key, "value", Ttl);

        Clock.Advance(Ttl);

        Assert.Null(await Storage.GetAsync(key));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DELETE
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Delete_ExistingKey_RemovesItAndReturnsTrue()
    {
        var key = NewKey();
        await Storage.SetAsync(key, "value", Ttl);

        Assert.True(await Storage.DeleteAsync(key));
        Assert.Null(await Storage.GetAsync(key));
        Assert.False(await Storage.DeleteAsync(key));
    }

    [Fact]
    public async Task Delete_MissingKey_ReturnsFalse()
    {
        Assert.False(await Storage.DeleteAsync(NewKey()));
    }

    [Fact]
    public async Task Delete_ExpiredKey_ReturnsFalse()
    {
        var key = NewKey();
        await Storage.SetAsync(key, "value", Ttl);
        Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.False(await Storage.DeleteAsync(key));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SET IF NOT EXISTS
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task SetIfNotExists_MissingKey_StoresValue()
    {
        var key = NewKey();

        Assert.True(await Storage.SetIfNotExistsAsync(key, "first", Ttl));
        Assert.Equal("first", await Storage.GetAsync(key));
    }

    [Fact]
    public async Task SetIfNotExists_Replayed_ReturnsFalseAndKeepsOriginal()
    {
        var key = NewKey();
        await Storage.SetIfNotExistsAsync(key, "first", Ttl);

        Assert.False(await Storage.SetIfNotExistsAsync(key, "second", Ttl));
        Assert.Equal("first", await Storage.GetAsync(key));
    }

    [Fact]
    public async Task SetIfNotExists_AfterExpiry_StoresAgain()
    {
        var key = NewKey();
        await Storage.SetIfNotExistsAsync(key, "first", Ttl);
        Clock.Advance(Ttl + TimeSpan.FromSeconds(1));

        Assert.True(await Storage.SetIfNotExistsAsync(key, "second", Ttl));
        Assert.Equal("second", await Storage.GetAsync(key));
    }

    [Fact]
    public virtual async Task SetIfNotExists_ParallelCallers_ExactlyOneWins()
    {
        var key = NewKey();

        IAegisSecondaryStorage storage = Storage;

        var results = await RunInParallelAsync(i => storage.SetIfNotExistsAsync(key, $"caller-{i}", Ttl));

        var winners = Enumerable.Range(0, ParallelCallers).Where(i => results[i]).ToList();
        Assert.Single(winners);
        Assert.Equal($"caller-{winners[0]}", await Storage.GetAsync(key));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INCREMENT
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task Increment_CountsFromOne()
    {
        var key = NewKey();

        Assert.Equal(1, await Storage.IncrementAsync(key, Ttl));
        Assert.Equal(2, await Storage.IncrementAsync(key, Ttl));
        Assert.Equal(3, await Storage.IncrementAsync(key, Ttl));
        Assert.Equal("3", await Storage.GetAsync(key));
    }

    [Fact]
    public async Task Increment_KeepsOriginalExpiry()
    {
        var key = NewKey();
        await Storage.IncrementAsync(key, Ttl);
        Clock.Advance(TimeSpan.FromSeconds(45));
        await Storage.IncrementAsync(key, Ttl);

        Clock.Advance(TimeSpan.FromSeconds(15));

        Assert.Null(await Storage.GetAsync(key));
        Assert.Equal(1, await Storage.IncrementAsync(key, Ttl));
    }

    [Fact]
    public async Task Increment_ExistingIntegerValue_ContinuesFromIt()
    {
        var key = NewKey();
        await Storage.SetAsync(key, "41", Ttl);

        Assert.Equal(42, await Storage.IncrementAsync(key, Ttl));
    }

    [Fact]
    public async Task Increment_NonIntegerValue_Throws()
    {
        var key = NewKey();
        await Storage.SetAsync(key, "not-a-number", Ttl);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Storage.IncrementAsync(key, Ttl));
    }

    [Fact]
    public virtual async Task Increment_ParallelCallers_NoIncrementIsLost()
    {
        var key = NewKey();

        IAegisSecondaryStorage storage = Storage;

        var results = await RunInParallelAsync(_ => storage.IncrementAsync(key, Ttl));

        Assert.Equal(Enumerable.Range(1, ParallelCallers).Select(i => (long)i), results.Order());
        Assert.Equal(ParallelCallers.ToString(System.Globalization.CultureInfo.InvariantCulture), await Storage.GetAsync(key));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ARGUMENTS
    // ═══════════════════════════════════════════════════════════════════════════

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task NonPositiveTtl_Throws(int seconds)
    {
        TimeSpan ttl = TimeSpan.FromSeconds(seconds);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Storage.SetAsync(NewKey(), "v", ttl));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Storage.SetIfNotExistsAsync(NewKey(), "v", ttl));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Storage.IncrementAsync(NewKey(), ttl));
    }

    [Fact]
    public async Task InvalidKey_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Storage.GetAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => Storage.SetAsync(new string('k', AegisStorageKey.MaxLength + 1), "v", Ttl));
    }

    [Fact]
    public async Task MaxLengthKey_IsAccepted()
    {
        var key = new string('k', AegisStorageKey.MaxLength);

        await Storage.SetAsync(key, "v", Ttl);

        Assert.Equal("v", await Storage.GetAsync(key));
    }

    /// <summary>Starts all callers together, so their operations actually overlap.</summary>
    protected static async Task<T[]> RunInParallelAsync<T>(Func<int, Task<T>> operation)
    {
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<T>[] tasks = Enumerable.Range(0, ParallelCallers)
            .Select(i => Task.Run(async () =>
            {
                await start.Task;
                return await operation(i);
            }))
            .ToArray();

        start.SetResult();
        return await Task.WhenAll(tasks);
    }
}
