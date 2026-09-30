namespace Aegis.Auth.Tests.Helpers;

/// <summary>A <see cref="TimeProvider"/> whose clock only moves when the test advances it.</summary>
internal sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private long _utcTicks = start.UtcTicks;

    public ManualTimeProvider() : this(DateTimeOffset.UtcNow) { }

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _utcTicks, by.Ticks);
}
