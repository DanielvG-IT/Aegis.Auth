using System.Globalization;

using Aegis.Auth.Constants;
using Aegis.Auth.Logging;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.RateLimit;

internal static class RateLimitEndpointExtensions
{
    /// <summary>
    /// Enforces <see cref="Options.RateLimitOptions.MaxAttemptsPerIpPerMinute"/> for this endpoint.
    /// This is an endpoint filter rather than the ASP.NET Core rate limiting middleware so the limit
    /// cannot be silently skipped when the host app forgets <c>app.UseRateLimiter()</c>.
    /// </summary>
    public static RouteHandlerBuilder RequireAegisRateLimit(this RouteHandlerBuilder builder, string operation) =>
        builder.AddEndpointFilter(async (context, next) =>
        {
            HttpContext httpContext = context.HttpContext;
            IRateLimitService rateLimiter = httpContext.RequestServices.GetRequiredService<IRateLimitService>();

            RateLimitDecision decision = rateLimiter.TryAcquireForClient(operation, httpContext.Connection.RemoteIpAddress);
            if (decision.IsAllowed)
            {
                return await next(context);
            }

            httpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(RateLimitEndpointExtensions))
                .RateLimitExceeded(operation);

            return TooManyRequests(httpContext, decision.RetryAfter);
        });

    // Same problem shape as Aegis.Auth.Http's AegisHttpResultMapper, which this project cannot reference.
    private static IResult TooManyRequests(HttpContext httpContext, TimeSpan? retryAfter)
    {
        if (retryAfter is TimeSpan delay)
        {
            httpContext.Response.Headers.RetryAfter = Math.Ceiling(delay.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        return Results.Problem(
            detail: "Too many requests. Please try again later.",
            title: "Too Many Requests",
            statusCode: StatusCodes.Status429TooManyRequests,
            type: $"https://httpstatuses.com/{StatusCodes.Status429TooManyRequests}",
            instance: httpContext.Request.Path,
            extensions: new Dictionary<string, object?>
            {
                ["errorCode"] = AuthErrors.RateLimit.TooManyRequests,
            });
    }
}
