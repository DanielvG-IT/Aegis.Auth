using Aegis.Auth.Abstractions;
using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Options;

using Microsoft.AspNetCore.Mvc;

namespace Aegis.Auth.Features.OAuth
{
    [ApiController]
    [Route("api/auth")]
    public sealed class OAuthController(IOAuthService oAuthService, SessionCookieHandler cookieManager, AegisAuthOptions options) : AegisControllerBase
    {
        private readonly SessionCookieHandler _cookieManager = cookieManager;
        private readonly IOAuthService _oauthService = oAuthService;
        private readonly AegisAuthOptions _options = options;

        [HttpGet("callback/{provider}")]
        public /*async*/ Task<IActionResult> Callback(string provider, [FromQuery] string? redirectUrl)
        {
            return null!;
        }
    }
}