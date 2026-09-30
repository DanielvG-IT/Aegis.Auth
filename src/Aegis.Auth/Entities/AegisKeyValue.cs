namespace Aegis.Auth.Entities;

/// <summary>
/// A secondary storage entry, used only when the database-backed secondary storage is enabled
/// (<c>AddAegisDatabaseSecondaryStorage()</c>). Expired rows are ignored and purged periodically.
/// </summary>
public class AegisKeyValue
{
    /// <summary>Namespaced key (<c>aegis:{pluginId}:{purpose}:{id}</c>), at most 256 characters.</summary>
    public string Key { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;

    /// <summary>UTC instant after which the entry no longer exists.</summary>
    public DateTime ExpiresAt { get; set; }
}
