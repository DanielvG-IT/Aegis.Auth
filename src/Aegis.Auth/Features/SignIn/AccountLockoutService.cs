using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Features.SignIn;

public interface IAccountLockoutService
{
    /// <summary>
    /// Clears the lockout and failed-attempt counter for a user. Expose this only behind
    /// your own admin authorization.
    /// </summary>
    Task<Result> UnlockAsync(string userId, CancellationToken cancellationToken = default);
}

internal sealed class AccountLockoutService(IAuthDbContext dbContext) : IAccountLockoutService
{
    private readonly IAuthDbContext _db = dbContext;

    public async Task<Result> UnlockAsync(string userId, CancellationToken cancellationToken = default)
    {
        User? user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);
        if (user is null)
        {
            return Result.Failure(AuthErrors.Identity.UserNotFound, "User not found.");
        }

        user.FailedSignInCount = 0;
        user.LockoutUntil = null;
        user.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);

        return Result.Success();
    }
}
