using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;

using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.SignIn
{

    [ApiController]
    public class SignInController(
        ISignInService signInService,
        IHostEnvironment env) : AegisControllerBase
    {
        [HttpPost("sign-in/email")]
        public async Task<IActionResult> SignInEmail([FromBody] SignInEmailRequest request)
        {
            // TODO Validate the input
            // var validated = request.verify()

            Result<SignInResult> result = await signInService.SignInEmail(
                request.Email,
                request.Password,
                request.Callback,
                request.RememberMe
            );

            if (!result.IsSuccess)
                return HandleResult(result);

            SignInResult? data = result.Value;
            if (data is null)
                return NotFound();

            Response.Cookies.Append("session", data.Session.Token, new CookieOptions
            {
                HttpOnly = true,
                Secure = !env.IsDevelopment(), // Secure only in Prod
                SameSite = SameSiteMode.Lax,
                Expires = data.Session.ExpiresAt,
                Path = "/" // available site-wide
            });

            return Ok(new SignInResponse
            {
                User = data.User.ToDto(),
                Token = data.Session.Token,
                Redirect = !string.IsNullOrWhiteSpace(request.Callback),
                Url = request.Callback
            });
        }
    }
}