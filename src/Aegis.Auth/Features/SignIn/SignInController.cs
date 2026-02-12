using Aegis.Auth.Extensions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Infrastructure.Cookies;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.SignIn
{

    [ApiController]
    [Route("api/auth")]
    public sealed class SignInController(ISignInService signInService, SessionCookieHandler cookieManager) : AegisControllerBase
    {
        [HttpPost("sign-in/email")]
        public async Task<IActionResult> SignInEmail([FromBody] SignInEmailRequest request)
        {
            // TODO Validate the signinemail input
            // var validated = request.verify()

            var emailInput = new SignInEmailInput
            {
                Email = request.Email,
                Password = request.Password,
                RememberMe = request.RememberMe,
                UserAgent = HttpContext.Request.Headers.UserAgent.ToString() ?? "unknown",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            };
            Result<SignInResult> result = await signInService.SignInEmail(emailInput);
            if (result.IsSuccess is false || result.Value is null)
                return HandleResult(result);

            SignInResult data = result.Value;

            cookieManager.SetSessionCookie(HttpContext, data.Session, data.User, request.RememberMe);

            var shouldRedirect = string.IsNullOrWhiteSpace(request.Callback) is false;
            if (shouldRedirect)
                HttpContext.Response.Headers.Location = request.Callback;

            return Ok(new SignInResponse
            {
                User = data.User.ToDto(),
                Token = data.Session.Token,
                Redirect = shouldRedirect,
                Url = shouldRedirect ? request.Callback : null
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