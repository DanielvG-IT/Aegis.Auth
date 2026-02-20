using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Infrastructure.Authentication
{
  internal sealed class AegisAuthenticationHandler(
      IOptionsMonitor<AuthenticationSchemeOptions> options,
      ILoggerFactory logger,
      UrlEncoder encoder,
      IAuthDbContext dbContext,
      SessionCookieHandler cookieHandler,
      AegisAuthOptions authOptions,
      IDistributedCache? cache = null) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
  {
    private readonly IAuthDbContext _dbContext = dbContext;
    private readonly SessionCookieHandler _cookieHandler = cookieHandler;
    private readonly AegisAuthOptions _authOptions = authOptions;
    private readonly IDistributedCache? _cache = cache;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
      var token = _cookieHandler.GetSessionToken(Context);
      if (string.IsNullOrWhiteSpace(token))
        return AuthenticateResult.NoResult();

      SessionPrincipalData? principalData = await TryResolveSessionFromCacheAsync(token);
      principalData ??= await TryResolveSessionFromDatabaseAsync(token);

      if (principalData is null)
        return AuthenticateResult.Fail("Invalid or expired session.");

      var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, principalData.UserId),
                new(ClaimTypes.Email, principalData.Email),
                new("aegis:session_id", principalData.SessionId),
                new("aegis:email_verified", principalData.EmailVerified ? "true" : "false")
            };

      if (string.IsNullOrWhiteSpace(principalData.Name) is false)
        claims.Add(new Claim(ClaimTypes.Name, principalData.Name));

      var identity = new ClaimsIdentity(claims, Scheme.Name);
      var principal = new ClaimsPrincipal(identity);
      var ticket = new AuthenticationTicket(principal, Scheme.Name);

      return AuthenticateResult.Success(ticket);
    }

    private async Task<SessionPrincipalData?> TryResolveSessionFromCacheAsync(string token)
    {
      if (_cache is null)
        return null;

      var sessionJson = await _cache.GetStringAsync(token, Context.RequestAborted);
      if (string.IsNullOrWhiteSpace(sessionJson))
        return null;

      SessionCacheJson? sessionCache;
      try
      {
        sessionCache = JsonSerializer.Deserialize<SessionCacheJson>(sessionJson);
      }
      catch
      {
        return null;
      }

      if (sessionCache?.Session is null || sessionCache.User is null)
        return null;

      if (sessionCache.Session.ExpiresAt <= DateTime.UtcNow)
        return null;

      return new SessionPrincipalData
      {
        SessionId = sessionCache.Session.Id,
        UserId = sessionCache.User.Id,
        Email = sessionCache.User.Email,
        Name = sessionCache.User.Name,
        EmailVerified = sessionCache.User.EmailVerified
      };
    }

    private async Task<SessionPrincipalData?> TryResolveSessionFromDatabaseAsync(string token)
    {
      if (_authOptions.Session.StoreSessionInDatabase is false && _cache is not null)
        return null;

      Session? session = await _dbContext.Sessions.AsNoTracking()
    .FirstOrDefaultAsync(s => s.Token == token, Context.RequestAborted);

      if (session is null || session.ExpiresAt <= DateTime.UtcNow)
        return null;

      User? user = await _dbContext.Users.AsNoTracking()
    .FirstOrDefaultAsync(u => u.Id == session.UserId, Context.RequestAborted);

      if (user is null)
        return null;

      return new SessionPrincipalData
      {
        SessionId = session.Id,
        UserId = user.Id,
        Email = user.Email,
        Name = user.Name,
        EmailVerified = user.EmailVerified
      };
    }

    private sealed class SessionPrincipalData
    {
      public required string SessionId { get; init; }
      public required string UserId { get; init; }
      public required string Email { get; init; }
      public string? Name { get; init; }
      public bool EmailVerified { get; init; }
    }
  }
}