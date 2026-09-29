namespace Aegis.Auth.Sample.Services;

public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken);
}

/// <summary>
/// Development stand-in for a real email provider: writes the message to the log so the
/// reset / verification links can be copied from the console.
/// Swap this for an SMTP or transactional-email implementation in production.
/// </summary>
public sealed class LoggingEmailSender(ILogger<LoggingEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string to, string subject, string body, CancellationToken cancellationToken)
    {
        logger.LogInformation("📧 Email to {To} | {Subject}\n{Body}", to, subject, body);
        return Task.CompletedTask;
    }
}
