using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Abstractions
{
    public interface IAegisLogger
    {
        void Trace(string message, params object[] args);
        void Debug(string message, params object[] args);
        void Info(string message, params object[] args);
        void Warning(string message, params object[] args);
        void Error(string message, Exception? ex = null, params object[] args);
        void Critical(string message, Exception? ex = null, params object[] args);
    }
}