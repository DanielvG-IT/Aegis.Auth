using Microsoft.Extensions.Caching.Distributed;

namespace Aegis.Auth.Options
{
    public sealed class AegisAuthOptions
    {
        public string AppName { get; set; } = string.Empty;
        public string BaseURL { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;
        public ICollection<string>? TrustedOrigins { get; set; }

        public EmailAndPasswordOptions EmailAndPassword { get; set; } = new();
        public OAuthOptions OAuth { get; set; } = new();
        public CsrfOptions Csrf { get; set; } = new();
        public RateLimitOptions RateLimit { get; set; } = new();
        public AccountLockoutOptions AccountLockout { get; set; } = new();

        public EmailVerificationOptions EmailVerification { get; set; } = new();

        public SessionOptions Session { get; set; } = new();
    }


}
