namespace Aegis.Auth.Options
{
    public sealed class SessionOptions
    {
        // public string? ModelName { get; set; }
        public int ExpiresIn { get; set; } = 60 * 60 * 24 * 7; // 7 days
        // public int? UpdateAge { get; set; }
        // public bool DisableSessionRefresh { get; set; } = false;
        // public Dictionary<string, object>? AdditionalFields { get; set; }
        public bool StoreSessionInDatabase { get; set; } = true;
        // public bool PreserveSessionInDatabase { get; set; } = false;
        // public int? FreshAge { get; set; }
        public CookieCacheOptions? CookieCache { get; set; }
    }

    public sealed class CookieCacheOptions
    {
        public int? MaxAge { get; set; }
        public bool Enabled { get; set; } = true;
        public string Version { get; set; } = "1";

        /// <summary>
        /// Controls how the session_data cookie payload is protected.
        /// Compact (default): HMAC-signed, Base64Url-encoded. Tamper-proof but readable.
        /// Encrypted: AES-256-GCM encrypted using a key derived from the application secret.
        ///            Provides confidentiality + integrity. Stateless across all instances.
        /// </summary>
        public CookieCacheMode Mode { get; set; } = CookieCacheMode.Compact;
    }

    /// <summary>
    /// Determines how the session cache cookie payload is protected.
    /// Both modes are fully stateless — any instance sharing the same secret can read/write.
    /// </summary>
    public enum CookieCacheMode
    {
        /// <summary>
        /// HMAC-signed, Base64Url-encoded JSON. Tamper-proof but payload is readable.
        /// Fastest option. Use when session data is non-sensitive.
        /// </summary>
        Compact,

        /// <summary>
        /// AES-256-GCM encrypted with HKDF-derived key from the application secret.
        /// Provides confidentiality + integrity. Payload is opaque to clients.
        /// </summary>
        Encrypted
    }
}
