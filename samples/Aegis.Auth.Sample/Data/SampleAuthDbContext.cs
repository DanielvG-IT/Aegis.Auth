using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Sample.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Data;

public class SampleAuthDbContext(DbContextOptions<SampleAuthDbContext> options) : DbContext(options), IAuthDbContext
{
    public DbSet<AppUser> Users { get; set; } = null!;
    public DbSet<Account> Accounts { get; set; } = null!;
    public DbSet<Session> Sessions { get; set; } = null!;
    public DbSet<Project> Projects { get; set; } = null!;
    public DbSet<ProjectTask> ProjectTasks { get; set; } = null!;

    DbSet<User> IAuthDbContext.Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyAegisAuthModel();

        // Add your app-specific entity mappings below.
        // Example: strongly typed extension of Aegis user entity.
        modelBuilder.Entity<AppUser>(entity =>
        {
            entity.HasBaseType<User>();
            entity.Property(u => u.IsSpecial).IsRequired();
        });

        modelBuilder.Entity<Project>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).HasMaxLength(120).IsRequired();
            entity.Property(e => e.Description).HasMaxLength(500);
            entity.HasIndex(e => e.OwnerUserId);
            entity.HasIndex(e => new { e.OwnerUserId, e.Name });

            // App business tables can reference auth users directly by User.Id.
            entity.HasOne<User>()
              .WithMany()
              .HasForeignKey(e => e.OwnerUserId)
              .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<ProjectTask>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Title).HasMaxLength(180).IsRequired();
            entity.HasIndex(e => e.ProjectId);
            entity.HasIndex(e => new { e.ProjectId, e.IsDone });

            entity.HasOne(e => e.Project)
              .WithMany(p => p.Tasks)
              .HasForeignKey(e => e.ProjectId)
              .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
