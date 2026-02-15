using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Logging;
using Aegis.Auth.Options;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Aegis.Auth.Entities;

namespace Aegis.Auth.Features.SignOut
{
    public interface ISignOutService
    {
        Task<Result> SignOut(SignOutInput input);
    }

    internal sealed class SignOutService(AegisAuthOptions options, ILoggerFactory loggerFactory, IAuthDbContext dbContext, ISessionService sessionService) : ISignOutService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly AegisAuthOptions _options = options;
        private readonly ISessionService _sessionService = sessionService;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SignOutService>();

        public async Task<Result> SignOut(SignOutInput input)
        {
            _logger.SignOutAttemptInitiated();

            // Look up the session to get the userId for registry cleanup
            Session? session = await _db.Sessions
                .Include(s => s.User)
                .FirstOrDefaultAsync(s => s.Token == input.Token);

            if (session is null)
            {
                _logger.SignOutSessionNotFound(input.Token);
                return Result.Failure(AuthErrors.Session.SessionNotFound, "Session not found or already expired.");
            }

            // Revoke session: cache -> registry -> DB
            var revokeInput = new SessionDeleteInput
            {
                User = session.User,
                Token = input.Token
            };

            Result result = await _sessionService.RevokeSessionAsync(revokeInput);
            if (result.IsSuccess is false)
            {
                _logger.SignOutRevocationFailed(input.Token);
                return result;
            }

            _logger.SignOutSuccessful(session.UserId);
            return Result.Success();
        }
    }
}
