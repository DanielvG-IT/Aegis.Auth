namespace Aegis.Auth.Options
{
    public sealed class SessionOptions
    {
        public string? ModelName { get; set; }
        public int ExpiresIn { get; set; } = 3600; // 1 hour in seconds
        public int? UpdateAge { get; set; }
        public bool DisableSessionRefresh { get; set; } = false;
        public Dictionary<string, object>? AdditionalFields { get; set; }
        public bool StoreSessionInDatabase { get; set; } = true;
        public bool PreserveSessionInDatabase { get; set; } = false;
        public CookieCacheOptions? CookieCache { get; set; }
        public int? FreshAge { get; set; }
    }

    public sealed class CookieCacheOptions
    {
        public int? MaxAge { get; set; }
        public bool Enabled { get; set; } = true;
        public CookieCacheStrategy Strategy { get; set; } = CookieCacheStrategy.Compact;
        public CookieCacheRefreshOptions? RefreshCache { get; set; }
        public string? Version { get; set; }
    }

    public sealed class CookieCacheRefreshOptions
    {
        public int? UpdateAge { get; set; }
    }

    public enum CookieCacheStrategy
    {
        Compact,
        Jwt,
        Jwe
    }
}