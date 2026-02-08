using Microsoft.EntityFrameworkCore;

using Aegis.Auth.Entities;

namespace Aegis.Auth.Abstractions
{
  public interface IAuthDbContext
  {
    DbSet<User> Users { get; }
    DbSet<Account> Accounts { get; }
    DbSet<Session> Sessions { get; }
    DbSet<Verification> Verifications { get; }

    Task<int> SaveChangesAsync(CancellationToken ct = default);
  }
}