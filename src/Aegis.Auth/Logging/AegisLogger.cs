using Aegis.Auth.Abstractions;
using Aegis.Auth.Options;

using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Logging
{
    internal sealed class AegisLogger(ILoggerFactory factory, AegisAuthOptions options) : IAegisLogger
    {
        private readonly ILogger _logger = factory.CreateLogger("Aegis.Auth");

        // Helper to check if we should even bother logging
        private bool IsEnabled(LogLevel level) => options.LogLevel != LogLevel.None && options.LogLevel <= level;

        // Sanitize user-provided values before logging to prevent log forging
        private static object[] SanitizeArgs(object[] args)
        {
            if (args is null || args.Length == 0)
                return args;

            var sanitized = new object[args.Length];
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] is string s)
                {
                    // Remove carriage returns, newlines, and other control characters
                    var filtered = new string(s.Where(c => !char.IsControl(c)).ToArray());
                    sanitized[i] = filtered;
                }
                else
                {
                    sanitized[i] = args[i];
                }
            }

            return sanitized;
        }

        public void Trace(string message, params object[] args)
        {
            if (IsEnabled(LogLevel.Trace))
            {
#pragma warning disable CA2254
                _logger.LogTrace(message, SanitizeArgs(args));
#pragma warning restore CA2254
            }
        }

        public void Debug(string message, params object[] args)
        {
            if (IsEnabled(LogLevel.Debug))
            {
#pragma warning disable CA2254
                _logger.LogDebug(message, SanitizeArgs(args));
#pragma warning restore CA2254
            }
        }

        public void Info(string message, params object[] args)
        {
            if (IsEnabled(LogLevel.Information))
            {
#pragma warning disable CA2254
                _logger.LogInformation(message, SanitizeArgs(args));
#pragma warning restore CA2254
            }
        }

        public void Warning(string message, params object[] args)
        {
            if (IsEnabled(LogLevel.Warning))
            {
#pragma warning disable CA2254
                _logger.LogWarning(message, SanitizeArgs(args));
#pragma warning restore CA2254
            }
        }

        public void Error(string message, Exception? ex = null, params object[] args)
        {
            if (IsEnabled(LogLevel.Error))
            {
#pragma warning disable CA2254
                _logger.LogError(ex, message, SanitizeArgs(args));
#pragma warning restore CA2254
            }
        }

        public void Critical(string message, Exception? ex = null, params object[] args)
        {
            if (IsEnabled(LogLevel.Critical))
            {
#pragma warning disable CA2254
                _logger.LogCritical(ex, message, SanitizeArgs(args));
#pragma warning restore CA2254
            }
        }
    }
}