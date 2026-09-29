using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;

using Aegis.Auth.Options;

using Microsoft.Extensions.Options;

namespace Aegis.Auth.Features.RateLimit;

internal readonly record struct RateLimitDecision(bool IsAllowed, TimeSpan? RetryAfter)
{
    public static RateLimitDecision Allowed { get; } = new(true, null);
}

internal interface IRateLimitService
{
    /// <summary>
    /// Consumes one attempt for <paramref name="operation"/> from the client's per-minute budget
    /// (<see cref="RateLimitOptions.MaxAttemptsPerIpPerMinute"/>).
    /// </summary>
    RateLimitDecision TryAcquireForClient(string operation, IPAddress? clientAddress);

    /// <summary>
    /// Consumes one sign-in attempt from the email's 15-minute budget
    /// (<see cref="RateLimitOptions.MaxAttemptsPerEmailPer15Minutes"/>).
    /// </summary>
    RateLimitDecision TryAcquireForEmail(string normalizedEmail);
}

/// <summary>
/// In-memory fixed-window limiter built on <see cref="PartitionedRateLimiter"/>, which evicts idle
/// partitions on its own so memory stays bounded by the clients active in the current window.
/// State is per process: with several instances each one enforces the limits independently.
/// </summary>
internal sealed class RateLimitService : IRateLimitService, IDisposable
{
    private const string UnknownClient = "unknown";

    private static readonly TimeSpan ClientWindow = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan EmailWindow = TimeSpan.FromMinutes(15);

    private readonly PartitionedRateLimiter<string>? _clientLimiter;
    private readonly PartitionedRateLimiter<string>? _emailLimiter;

    public RateLimitService(IOptions<AegisAuthOptions> optionsAccessor)
    {
        RateLimitOptions options = optionsAccessor.Value.RateLimit;
        if (options.Enabled is false)
        {
            return;
        }

        _clientLimiter = CreateFixedWindowLimiter(options.MaxAttemptsPerIpPerMinute, ClientWindow);
        _emailLimiter = CreateFixedWindowLimiter(options.MaxAttemptsPerEmailPer15Minutes, EmailWindow);
    }

    public RateLimitDecision TryAcquireForClient(string operation, IPAddress? clientAddress) =>
        TryAcquire(_clientLimiter, $"{operation}|{GetClientPartitionKey(clientAddress)}");

    public RateLimitDecision TryAcquireForEmail(string normalizedEmail) =>
        TryAcquire(_emailLimiter, normalizedEmail);

    public void Dispose()
    {
        _clientLimiter?.Dispose();
        _emailLimiter?.Dispose();
    }

    /// <summary>
    /// IPv6 clients usually control a whole /64, so rotating the interface identifier must not
    /// reset their budget. IPv4-mapped addresses share the bucket of the plain IPv4 address.
    /// </summary>
    internal static string GetClientPartitionKey(IPAddress? address)
    {
        if (address is null)
        {
            return UnknownClient;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily is not AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        bytes[8..].Clear();
        return $"{new IPAddress(bytes)}/64";
    }

    private static RateLimitDecision TryAcquire(PartitionedRateLimiter<string>? limiter, string partitionKey)
    {
        if (limiter is null)
        {
            return RateLimitDecision.Allowed;
        }

        using RateLimitLease lease = limiter.AttemptAcquire(partitionKey);
        if (lease.IsAcquired)
        {
            return RateLimitDecision.Allowed;
        }

        return lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter)
            ? new RateLimitDecision(false, retryAfter)
            : new RateLimitDecision(false, null);
    }

    private static PartitionedRateLimiter<string> CreateFixedWindowLimiter(int permitLimit, TimeSpan window) =>
        PartitionedRateLimiter.Create<string, string>(partitionKey =>
            RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = window,
                QueueLimit = 0,
                AutoReplenishment = true,
            }));
}
