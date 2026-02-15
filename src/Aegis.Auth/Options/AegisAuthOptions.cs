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

        // ═══════════════════════════════════════════════════════════════════════════════
        // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
        // ═══════════════════════════════════════════════════════════════════════════════
        // TODO v0.2: Uncomment this property for email verification support
        // public EmailVerificationOptions? EmailVerification { get; set; }
        // ═══════════════════════════════════════════════════════════════════════════════

        public SessionOptions Session { get; set; } = new();
    }


}