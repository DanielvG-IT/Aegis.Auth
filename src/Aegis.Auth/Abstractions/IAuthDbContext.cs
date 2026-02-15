using Microsoft.EntityFrameworkCore;

using Aegis.Auth.Entities;

namespace Aegis.Auth.Abstractions
{
  public interface IAuthDbContext
  {
    DbSet<User> Users { get; }
    DbSet<Account> Accounts { get; }
    DbSet<Session> Sessions { get; }

    // ═══════════════════════════════════════════════════════════════════════════════
    // EMAIL VERIFICATION - DISABLED FOR v0.1, WILL BE RE-ENABLED IN v0.2
    // ═══════════════════════════════════════════════════════════════════════════════
    // TODO v0.2: Uncomment this for email verification support
    // DbSet<Verification> Verifications { get; }
    // ═══════════════════════════════════════════════════════════════════════════════

    Task<int> SaveChangesAsync(CancellationToken ct = default);
  }
}