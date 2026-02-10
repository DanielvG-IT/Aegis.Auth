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
    var userCount = await _context.Users.CountAsync();
    var accountCount = await _context.Accounts.CountAsync();

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
        requireEmailVerification = _options.EmailAndPassword.RequireEmailVerification,
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
        .Include(u => u.Accounts)
        .Include(u => u.Sessions)
        .Select(u => new
        {
          u.Id,
          u.Email,
          u.Name,
          u.IsEmailVerified,
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
