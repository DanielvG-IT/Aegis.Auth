using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Core.Crypto;
using Aegis.Auth.Entities;
using Aegis.Auth.Features.Sessions;
using Aegis.Auth.Logging;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Features.SignOut
{
    public interface ISignOutService
    {
        Task<Result> SignOut(SignOutInput input, CancellationToken cancellationToken = default);
    }

    internal sealed class SignOutService(ILoggerFactory loggerFactory, IAuthDbContext dbContext, ISessionService sessionService) : ISignOutService
    {
        private readonly IAuthDbContext _db = dbContext;
        private readonly ISessionService _sessionService = sessionService;
        private readonly ILogger _logger = loggerFactory.CreateLogger<SignOutService>();

        public async Task<Result> SignOut(SignOutInput input, CancellationToken cancellationToken = default)
        {
            _logger.SignOutAttemptInitiated();

            // Hash before querying; the database only stores the hash of the raw token.
            var tokenHash = AegisCrypto.HashToken(input.Token);
            Session? session = await _db.Sessions
                .Include(s => s.User)
                .FirstOrDefaultAsync(s => s.TokenHash == tokenHash, cancellationToken);

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

            Result result = await _sessionService.RevokeSessionAsync(revokeInput, cancellationToken);
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
