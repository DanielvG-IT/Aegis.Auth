using Aegis.Auth.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Abstractions
{
    public interface IAuthDbContext
    {
        DbSet<User> Users { get; }
        DbSet<Account> Accounts { get; }
        DbSet<Session> Sessions { get; }
        DbSet<AuthToken> AuthTokens { get; }

        Task<int> SaveChangesAsync(CancellationToken ct = default);
    }
}
