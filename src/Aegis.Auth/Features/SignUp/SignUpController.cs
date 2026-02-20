using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.SignUp
{
    [ApiController]
    [Route("api/auth")]
    public sealed class SignUpController(ISignUpService signUpService, SessionCookieHandler cookieManager, AegisAuthOptions options) : AegisControllerBase
    {
        private readonly SessionCookieHandler _cookieManager = cookieManager;
        private readonly ISignUpService _signUpService = signUpService;
        private readonly AegisAuthOptions _options = options;

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
            Result<SignUpResult> result = await _signUpService.SignUpEmail(emailInput);
            if (result.IsSuccess is false || result.Value is null)
                return HandleResult(result);

            SignUpResult data = result.Value;

            if (data.Session is not null)
                _cookieManager.SetSessionCookie(HttpContext, data.Session, data.User, false);

            var validatedCallback = ValidateCallback(request.Callback, _options);
            var shouldRedirect = validatedCallback is not null;
            if (shouldRedirect)
                HttpContext.Response.Headers.Location = validatedCallback;

            return Ok(new SignUpResponse
            {
                User = data.User.ToDto(),
                Token = data.Session?.Token,
                Redirect = shouldRedirect,
                Url = validatedCallback
            });
        }
    }
}
