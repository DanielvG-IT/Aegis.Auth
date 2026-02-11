using Aegis.Auth.Options;
using Aegis.Auth.Sample.Data;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController(SampleAuthDbContext context, AegisAuthOptions options) : ControllerBase
{
  private readonly SampleAuthDbContext _context = context;
  private readonly AegisAuthOptions _options = options;

  [HttpGet]
  public async Task<IActionResult> Get()
  {
    var userCount = await _context.Users.AsNoTracking().CountAsync();
    var accountCount = await _context.Accounts.AsNoTracking().CountAsync();

    return Ok(new
    {
      status = "healthy",
      timestamp = DateTime.UtcNow,
      database = new
      {
        users = userCount,
        accounts = accountCount
      },
      aegisAuth = new
      {
        appName = _options.AppName,
        baseUrl = _options.BaseURL,
        emailPasswordEnabled = _options.EmailAndPassword.Enabled,
        // requireEmailVerification = disabled for v0.1 (will be in v0.2)
        sessionExpiresIn = _options.Session.ExpiresIn,
        cookieCacheEnabled = _options.Session.CookieCache?.Enabled ?? false
      },
      testCredentials = new
      {
        email = "test@example.com",
        password = "Password123!"
      }
    });
  }

  [HttpGet("users")]
  public async Task<IActionResult> GetUsers()
  {
    var users = await _context.Users
        .AsNoTracking()
        .Select(u => new
        {
          u.Id,
          u.Email,
          u.Name,
          u.EmailVerified,
          u.CreatedAt,
          accountCount = u.Accounts.Count,
          sessionCount = u.Sessions.Count,
          accounts = u.Accounts.Select(a => new
          {
            a.Id,
            a.ProviderId,
            a.AccountId,
            hasPassword = !string.IsNullOrEmpty(a.PasswordHash)
          })
        })
        .ToListAsync();

    return Ok(users);
  }
}
