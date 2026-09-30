using Aegis.Auth.Abstractions;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Extensions;

public static class AuthDbContextExtensions
{
    /// <summary>
    /// The EF <see cref="DbContext"/> behind <paramref name="dbContext"/>. Plugins use it to reach their own
    /// tables (<c>Set&lt;TEntity&gt;()</c>), shadow properties (<c>Entry(…).Property(…)</c>) and transactions
    /// (<c>Database</c>), which <see cref="IAuthDbContext"/> does not expose.
    /// </summary>
    public static DbContext GetDbContext(this IAuthDbContext dbContext)
    {
        ArgumentNullException.ThrowIfNull(dbContext);

        return dbContext as DbContext
            ?? throw new InvalidOperationException(
                $"{dbContext.GetType().FullName} implements IAuthDbContext but is not an EF Core DbContext. Aegis plugins need a DbContext.");
    }
}
