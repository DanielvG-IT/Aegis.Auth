using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Infrastructure.EntityFramework;
using Aegis.Auth.Plugins;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Tests.Features;

/// <summary>
/// UseAegisAuth on a relational provider: core and plugin tables are created without any
/// OnModelCreating, and the provider's own model customizer is wrapped rather than replaced.
/// </summary>
public sealed class PluginModelSqliteTests
{
    [Fact]
    public async Task UseAegisAuth_Sqlite_CreatesCoreAndPluginTables_AndWrapsProviderCustomizer()
    {
        await using var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<SqliteAuthDbContext>((sp, o) => o.UseSqlite(connection).UseAegisAuth(sp));
        services.AddAegisAuth<SqliteAuthDbContext>().AddPlugin(new NotePlugin());
        await using ServiceProvider provider = services.BuildServiceProvider();

        using IServiceScope scope = provider.CreateScope();
        SqliteAuthDbContext db = scope.ServiceProvider.GetRequiredService<SqliteAuthDbContext>();
        await db.Database.EnsureCreatedAsync();

        Assert.NotNull(db.Model.FindEntityType(typeof(Note)));
        Assert.NotNull(db.Model.FindEntityType(typeof(AuthToken)));
        AegisAuthModelCustomizer customizer = Assert.IsType<AegisAuthModelCustomizer>(db.GetService<IModelCustomizer>());
        Assert.IsType<RelationalModelCustomizer>(customizer.Inner);

        db.Add(new Note { Id = "n1", Text = "hello" });
        await db.SaveChangesAsync();
        Assert.Equal(1, await db.Set<Note>().CountAsync());

        // Core index from the Aegis model is enforced by the database.
        db.Users.Add(new User { Id = "u1", Email = "dup@test.com", Name = "A" });
        db.Users.Add(new User { Id = "u2", Email = "dup@test.com", Name = "B" });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    internal sealed class Note
    {
        public string Id { get; set; } = string.Empty;
        public string Text { get; set; } = string.Empty;
    }

    private sealed class NotePlugin : AegisPlugin
    {
        public override string Id => "notes";

        public override void ConfigureModel(ModelBuilder modelBuilder) =>
            modelBuilder.Entity<Note>(e =>
            {
                e.HasKey(n => n.Id);
                e.Property(n => n.Text).HasMaxLength(200);
            });
    }

    internal sealed class SqliteAuthDbContext(DbContextOptions<SqliteAuthDbContext> options) : DbContext(options), IAuthDbContext
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<Account> Accounts => Set<Account>();
        public DbSet<Session> Sessions => Set<Session>();
        public DbSet<AuthToken> AuthTokens => Set<AuthToken>();
        public DbSet<AegisKeyValue> AegisKeyValues => Set<AegisKeyValue>();

        Task<int> IAuthDbContext.SaveChangesAsync(CancellationToken ct) => base.SaveChangesAsync(ct);
    }
}
