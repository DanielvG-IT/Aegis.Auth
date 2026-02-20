using Aegis.Auth.Options;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Features.Sessions;

using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.OAuth
{
    public interface IOAuthService { }

    internal sealed class OAuthService(AegisAuthOptions options, ILoggerFactory loggerFactory, IAuthDbContext dbContext, ISessionService sessionService) : IOAuthService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly AegisAuthOptions _options = options;
        private readonly ISessionService _sessionService = sessionService;
        private readonly ILogger _logger = loggerFactory.CreateLogger<OAuthService>();
    }
}