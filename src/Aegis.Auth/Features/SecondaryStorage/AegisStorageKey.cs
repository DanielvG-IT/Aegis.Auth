namespace Aegis.Auth.Features.SecondaryStorage;

/// <summary>
/// Builds namespaced secondary storage keys of the form <c>aegis:{pluginId}:{purpose}:{id}</c>,
/// so features sharing one store cannot collide.
/// </summary>
public static class AegisStorageKey
{
    /// <summary>Maximum key length accepted by every <see cref="IAegisSecondaryStorage"/> implementation.</summary>
    public const int MaxLength = 256;

    /// <summary>
    /// Creates <c>aegis:{pluginId}:{purpose}:{id}</c>. <paramref name="pluginId"/> and <paramref name="purpose"/>
    /// must not contain ':'. When <paramref name="id"/> is derived from a secret, pass its hash.
    /// </summary>
    public static string Create(string pluginId, string purpose, string id)
    {
        ValidateSegment(pluginId, nameof(pluginId));
        ValidateSegment(purpose, nameof(purpose));
        ArgumentException.ThrowIfNullOrEmpty(id);

        var key = $"aegis:{pluginId}:{purpose}:{id}";
        if (key.Length > MaxLength)
        {
            throw new ArgumentException($"Secondary storage keys are limited to {MaxLength} characters; hash long identifiers.", nameof(id));
        }

        return key;
    }

    private static void ValidateSegment(string value, string paramName)
    {
        ArgumentException.ThrowIfNullOrEmpty(value, paramName);
        if (value.Contains(':', StringComparison.Ordinal))
        {
            throw new ArgumentException("Key segments must not contain ':'.", paramName);
        }
    }
}
