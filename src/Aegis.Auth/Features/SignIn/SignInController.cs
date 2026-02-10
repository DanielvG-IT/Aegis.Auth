using Aegis.Auth.Extensions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Infrastructure.Cookies;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.SignIn
{

    [ApiController]
    [Route("api/auth")]
    public class SignInController(
        ISignInService signInService,
        AegisCookieManager cookieManager
        ) : AegisControllerBase
    {
        [HttpPost("sign-in/email")]
        public async Task<IActionResult> SignInEmail([FromBody] SignInEmailRequest request)
        {
            // TODO Validate the signinemail input
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
                return HandleResult(result); // TODO Add extra checks

            cookieManager.SetSessionCookie(HttpContext, data.Session, data.User, request.RememberMe);

            return Ok(new SignInResponse
            {
                User = data.User.ToDto(),
                Token = data.Session.Token,
                Redirect = !string.IsNullOrWhiteSpace(request.Callback),
                Url = request.Callback
            });
        }

        // [HttpPost("sign-in/social")]
        // public async Task<IActionResult> SignInSocial([FromBody] SignInSocialRequest request)
        // {
        //     Result<SignInResult> result = await signInService.SignInSocial();
        //     return null!;
        // }
    }
}