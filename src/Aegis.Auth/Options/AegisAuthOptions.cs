using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Options
{
    public sealed class AegisAuthOptions
    {
        public string AppName { get; set; } = string.Empty;
        public string BaseURL { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;
        public ICollection<string>? TrustedOrigins { get; set; } = [];
        public LogLevel LogLevel { get; set; } = LogLevel.Warning;

        public EmailAndPasswordOptions EmailAndPassword { get; set; } = new();
        public EmailVerificationOptions? EmailVerification { get; set; } = null;
        public SessionOptions Session { get; set; } = new();
    }


}