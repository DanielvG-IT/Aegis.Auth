using Aegis.Auth.Abstractions;
using Aegis.Auth.Core.Security;
using Aegis.Auth.Entities;
using Aegis.Auth.Infrastructure.Cookies;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Core.Sessions
{
  /// <summary>
  /// Default implementation of session management.
  /// Shared by all authentication methods (email/password, passkeys, OAuth, etc.)
  /// </summary>
  public sealed class AegisSessionService : IAegisSessionService
  {
    private readonly IAuthDbContext _dbContext;
    private readonly TokenGenerator _tokenGenerator;
    private readonly AegisCookieManager _cookieManager;

    public AegisSessionService(
        IAuthDbContext dbContext,
        TokenGenerator tokenGenerator,
        AegisCookieManager cookieManager)
    {
      _dbContext = dbContext;
      _tokenGenerator = tokenGenerator;
      _cookieManager = cookieManager;
    }

    public async Task<Session> CreateSessionAsync(
        User user,
        HttpContext context,
        CancellationToken cancellationToken = default)
    {
      var sessionToken = _tokenGenerator.GenerateSessionToken();

      var session = new Session
      {
        Id = Guid.NewGuid().ToString(),
        UserId = user.Id,
        Token = sessionToken,
        ExpiresAt = DateTime.UtcNow.AddDays(30),
        CreatedAt = DateTime.UtcNow,
        IpAddress = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
        UserAgent = context.Request.Headers.UserAgent.ToString()
      };

      _dbContext.Sessions.Add(session);
      await _dbContext.SaveChangesAsync(cancellationToken);

      _cookieManager.SetSessionCookie(context, sessionToken);

      return session;
    }

    public async Task InvalidateSessionAsync(
        string sessionId,
        HttpContext context,
        CancellationToken cancellationToken = default)
    {
      var session = await _dbContext.Sessions.FindAsync(new[] { sessionId }, cancellationToken);
      if (session != null)
      {
        _dbContext.Sessions.Remove(session);
        await _dbContext.SaveChangesAsync(cancellationToken);
      }

      _cookieManager.ClearSessionCookie(context);
    }
  }
}
