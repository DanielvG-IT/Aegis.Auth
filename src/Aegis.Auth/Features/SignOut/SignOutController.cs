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

            // 2. Revoke session (cache -> registry -> DB)
            var input = new SignOutInput { Token = token };
            Result result = await signOutService.SignOut(input);

            // 3. Always clear cookies, even if revocation fails or session is already gone
            _cookieHandler.ClearSessionCookies(HttpContext);

            if (result.IsSuccess is false)
                return HandleResult(result);

            return Ok(new SignOutResponse { Success = true });
        }
    }
}
