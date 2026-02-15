using Aegis.Auth.Abstractions;
using Aegis.Auth.Infrastructure.Cookies;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.SignOut
{
    [ApiController]
    [Route("api/auth")]
    public sealed class SignOutController(ISignOutService signOutService, SessionCookieHandler cookieHandler) : AegisControllerBase
    {
        private readonly SessionCookieHandler _cookieHandler = cookieHandler;

        [HttpPost("sign-out")]
        public new async Task<IActionResult> SignOut()
        {
            // 1. Read & verify the session token from the cookie
            var token = _cookieHandler.GetSessionToken(HttpContext);

            // 2. Always clear cookies first
            _cookieHandler.ClearSessionCookies(HttpContext);

            // 3. If no valid token, return early (user already signed out or tampered cookie)
            if (string.IsNullOrWhiteSpace(token))
            {
                return Ok(new SignOutResponse { Success = true });
            }

            // 4. Revoke session (cache -> registry -> DB)
            var input = new SignOutInput { Token = token };
            Result result = await signOutService.SignOut(input);

            if (result.IsSuccess is false)
                return HandleResult(result);

            return Ok(new SignOutResponse { Success = true });
        }
    }
}
