using Aegis.Auth.Extensions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Infrastructure.Cookies;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.SignUp
{

    [ApiController]
    [Route("api/auth")]
    public sealed class SignUpController(ISignUpService signUpService, SessionCookieHandler cookieManager) : AegisControllerBase
    {
        private readonly SessionCookieHandler _cookieManager = cookieManager;

        [HttpPost("sign-up/email")]
        public async Task<IActionResult> SignUpEmail([FromBody] SignUpEmailRequest request)
        {
            // TODO Validate the SignUpemail input
            // var validated = request.verify()

            var emailInput = new SignUpEmailInput
            {
                Name = request.Name,
                Image = request.Image,
                Email = request.Email,
                Password = request.Password,
                UserAgent = HttpContext.Request.Headers.UserAgent.ToString() ?? "unknown",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            };
            Result<SignUpResult> result = await signUpService.SignUpEmail(emailInput);
            if (result.IsSuccess is false || result.Value is null)
                return HandleResult(result);

            SignUpResult data = result.Value;

            if (data.Session is not null)
                _cookieManager.SetSessionCookie(HttpContext, data.Session, data.User, false);

            var shouldRedirect = string.IsNullOrWhiteSpace(request.Callback) is false;
            if (shouldRedirect)
                HttpContext.Response.Headers.Location = request.Callback;

            return Ok(new SignUpResponse
            {
                User = data.User.ToDto(),
                Token = data.Session?.Token,
                Redirect = shouldRedirect,
                Url = shouldRedirect ? request.Callback : null
            });
        }
    }
}