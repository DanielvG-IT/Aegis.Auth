using System.Text.RegularExpressions;

using Aegis.Auth.Constants;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Plugins;

/// <summary>
/// The plugins registered for this app, plus everything merged from them.
/// Filled while services are registered and read-only afterwards.
/// </summary>
internal sealed partial class AegisPluginRegistry
{
    private static readonly Dictionary<string, int> CoreErrorStatusCodes = new(StringComparer.Ordinal)
    {
        [AuthErrors.Identity.InvalidCredentials] = StatusCodes.Status401Unauthorized,
        [AuthErrors.Identity.InvalidEmailOrPassword] = StatusCodes.Status401Unauthorized,
        [AuthErrors.Identity.EmailNotVerified] = StatusCodes.Status403Forbidden,
        [AuthErrors.Identity.AccountLocked] = StatusCodes.Status403Forbidden,
        [AuthErrors.System.FeatureDisabled] = StatusCodes.Status403Forbidden,
        [AuthErrors.System.ProviderNotFound] = StatusCodes.Status404NotFound,
        [AuthErrors.Session.SessionNotFound] = StatusCodes.Status404NotFound,
        [AuthErrors.RateLimit.TooManyRequests] = StatusCodes.Status429TooManyRequests,
        [AuthErrors.System.InternalError] = StatusCodes.Status500InternalServerError,
        [AuthErrors.System.FailedToCreateSession] = StatusCodes.Status500InternalServerError,
    };

    private readonly List<AegisPlugin> _plugins = [];
    private readonly Dictionary<string, int> _errorStatusCodes = new(CoreErrorStatusCodes, StringComparer.Ordinal);
    private readonly List<(string PluginId, AegisRateLimitRule Rule)> _rateLimitRules = [];

    public IReadOnlyList<AegisPlugin> Plugins => _plugins;

    public IReadOnlyDictionary<string, int> ErrorStatusCodes => _errorStatusCodes;

    public IReadOnlyList<(string PluginId, AegisRateLimitRule Rule)> RateLimitRules => _rateLimitRules;

    public int GetStatusCode(string? errorCode) =>
        errorCode is not null && _errorStatusCodes.TryGetValue(errorCode, out var status)
            ? status
            : StatusCodes.Status400BadRequest;

    /// <summary>
    /// Status for <paramref name="errorCode"/> using only the core map, for apps that call
    /// the HTTP helpers without <c>AddAegisAuth</c> having run.
    /// </summary>
    public static int GetCoreStatusCode(string? errorCode) =>
        errorCode is not null && CoreErrorStatusCodes.TryGetValue(errorCode, out var status)
            ? status
            : StatusCodes.Status400BadRequest;

    public void Add(AegisPlugin plugin)
    {
        var id = plugin.Id;
        if (string.IsNullOrEmpty(id) || PluginIdPattern().IsMatch(id) is false)
        {
            throw new InvalidOperationException(
                $"Aegis plugin {plugin.GetType().FullName} has id '{id}'. Plugin ids must be kebab-case, e.g. 'organization'.");
        }

        if (_plugins.Any(p => string.Equals(p.Id, id, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"An Aegis plugin with id '{id}' is already registered. Each plugin can be added once.");
        }

        // Check everything before changing any state, so a rejected plugin leaves no trace.
        var errorStatusCodes = plugin.ErrorStatusCodes.ToList();
        foreach ((var code, var status) in errorStatusCodes)
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                throw new InvalidOperationException($"Aegis plugin '{id}' declares an empty error code.");
            }

            if (status is < 400 or > 599)
            {
                throw new InvalidOperationException(
                    $"Aegis plugin '{id}' maps error code '{code}' to {status}; error statuses must be between 400 and 599.");
            }

            if (_errorStatusCodes.TryGetValue(code, out var existing) && existing != status)
            {
                throw new InvalidOperationException(
                    $"Aegis plugin '{id}' maps error code '{code}' to {status}, but it is already mapped to {existing}.");
            }
        }

        var rateLimitRules = plugin.RateLimitRules.ToList();
        foreach (AegisRateLimitRule rule in rateLimitRules)
        {
            if (string.IsNullOrWhiteSpace(rule.Path) || rule.Path.StartsWith('/') is false)
            {
                throw new InvalidOperationException($"Aegis plugin '{id}' has a rate-limit rule with path '{rule.Path}'; paths must start with '/'.");
            }

            if (rule.MaxRequests is <= 0)
            {
                throw new InvalidOperationException($"Aegis plugin '{id}' has a rate-limit rule for '{rule.Path}' with MaxRequests <= 0.");
            }

            if (rule.Window is TimeSpan window && window <= TimeSpan.Zero)
            {
                throw new InvalidOperationException($"Aegis plugin '{id}' has a rate-limit rule for '{rule.Path}' with a non-positive Window.");
            }
        }

        _plugins.Add(plugin);
        foreach ((var code, var status) in errorStatusCodes)
        {
            _errorStatusCodes[code] = status;
        }

        _rateLimitRules.AddRange(rateLimitRules.Select(rule => (id, rule)));
    }

    [GeneratedRegex("^[a-z0-9]+(-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex PluginIdPattern();
}
