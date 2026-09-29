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

        /// <summary>
        /// Entries of the database-backed secondary storage (<c>AddAegisDatabaseSecondaryStorage()</c>).
        /// Mapped by <c>ApplyAegisAuthModel</c>; the table is unused with the other storage implementations.
        /// </summary>
        DbSet<AegisKeyValue> AegisKeyValues { get; }

        Task<int> SaveChangesAsync(CancellationToken ct = default);
    }
}
