namespace Aegis.Auth.Options;

public sealed class CsrfOptions
{
    /// <summary>
    /// Enable CSRF protection on state-changing auth endpoints (sign-in, sign-up, sign-out).
    /// Default: true. Should be disabled only for testing or special API scenarios.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Name of the HTTP header that carries the CSRF token. Default: X-CSRF-Token.
    /// </summary>
    public string HeaderName { get; set; } = "X-CSRF-Token";

    /// <summary>
    /// Name of the signed cookie that carries the CSRF token. Default: aegis.csrf / __Host-aegis.csrf.
    /// </summary>
    public string CookieName { get; set; } = "aegis.csrf";

    /// <summary>
    /// TTL of the CSRF token cookie in seconds. Default: 900 (15 minutes).
    /// </summary>
    public int CookieMaxAge { get; set; } = 900;
}
