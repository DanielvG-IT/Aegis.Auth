using Aegis.Auth.Sample.Data;
using Aegis.Auth.Sample.Entities;

using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Services;

public sealed class UserTierProfile
{
    public required string UserId { get; init; }
    public required bool IsSpecial { get; init; }
    public required string Tier { get; init; }
    public required int MaxProjects { get; init; }
    public required int MaxTasksPerProject { get; init; }
}

public sealed class ProjectSummaryDto
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? Description { get; init; }
    public required DateTime CreatedAt { get; init; }
    public required DateTime UpdatedAt { get; init; }
    public required int TotalTasks { get; init; }
    public required int CompletedTasks { get; init; }
}

public sealed class ProjectTasksDto
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? Description { get; init; }
    public required List<ProjectTaskDto> Tasks { get; init; }
}

public sealed class ProjectTaskDto
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required bool IsDone { get; init; }
    public required DateTime CreatedAt { get; init; }
    public DateTime? CompletedAt { get; init; }
}

public sealed class CreateProjectResult
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public string? Description { get; init; }
    public required DateTime CreatedAt { get; init; }
    public required DateTime UpdatedAt { get; init; }
}

public sealed class AddProjectTaskResult
{
    public required string Id { get; init; }
    public required string ProjectId { get; init; }
    public required string Title { get; init; }
    public required bool IsDone { get; init; }
    public required DateTime CreatedAt { get; init; }
    public DateTime? CompletedAt { get; init; }
}

public interface IProjectWorkspaceService
{
    Task<UserTierProfile?> GetTierProfileAsync(string userId, CancellationToken cancellationToken = default);
    Task<List<ProjectSummaryDto>> GetProjectsForUserAsync(string userId, CancellationToken cancellationToken = default);
    Task<CreateProjectResult?> CreateProjectAsync(string userId, string name, string? description, CancellationToken cancellationToken = default);
    Task<ProjectTasksDto?> GetProjectTasksAsync(string userId, string projectId, CancellationToken cancellationToken = default);
    Task<AddProjectTaskResult?> AddTaskAsync(string userId, string projectId, string title, CancellationToken cancellationToken = default);
}

public sealed class ProjectWorkspaceService(SampleAuthDbContext dbContext) : IProjectWorkspaceService
{
    private readonly SampleAuthDbContext _db = dbContext;

    public async Task<UserTierProfile?> GetTierProfileAsync(string userId, CancellationToken cancellationToken = default)
    {
        var profile = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.Id, u.IsSpecial })
            .FirstOrDefaultAsync(cancellationToken);

        if (profile is null)
        {
            return null;
        }

        var isSpecial = profile.IsSpecial;
        return new UserTierProfile
        {
            UserId = profile.Id,
            IsSpecial = isSpecial,
            Tier = isSpecial ? "special" : "standard",
            MaxProjects = isSpecial ? 10 : 3,
            MaxTasksPerProject = isSpecial ? 100 : 25,
        };
    }

    public async Task<List<ProjectSummaryDto>> GetProjectsForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        return await _db.Projects
            .AsNoTracking()
            .Where(p => p.OwnerUserId == userId)
            .OrderByDescending(p => p.UpdatedAt)
            .Select(p => new ProjectSummaryDto
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                CreatedAt = p.CreatedAt,
                UpdatedAt = p.UpdatedAt,
                TotalTasks = p.Tasks.Count,
                CompletedTasks = p.Tasks.Count(t => t.IsDone),
            })
            .ToListAsync(cancellationToken);
    }

    public async Task<CreateProjectResult?> CreateProjectAsync(string userId, string name, string? description, CancellationToken cancellationToken = default)
    {
        UserTierProfile? profile = await GetTierProfileAsync(userId, cancellationToken);
        if (profile is null)
        {
            return null;
        }

        var currentProjectCount = await _db.Projects
            .AsNoTracking()
            .CountAsync(p => p.OwnerUserId == userId, cancellationToken);

        if (currentProjectCount >= profile.MaxProjects)
        {
            return null;
        }

        DateTime now = DateTime.UtcNow;
        var project = new Project
        {
            Id = Guid.CreateVersion7().ToString(),
            OwnerUserId = userId,
            Name = name.Trim(),
            Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.Projects.Add(project);
        await _db.SaveChangesAsync(cancellationToken);

        return new CreateProjectResult
        {
            Id = project.Id,
            Name = project.Name,
            Description = project.Description,
            CreatedAt = project.CreatedAt,
            UpdatedAt = project.UpdatedAt,
        };
    }

    public async Task<ProjectTasksDto?> GetProjectTasksAsync(string userId, string projectId, CancellationToken cancellationToken = default)
    {
        return await _db.Projects
            .AsNoTracking()
            .Where(p => p.Id == projectId && p.OwnerUserId == userId)
            .Select(p => new ProjectTasksDto
            {
                Id = p.Id,
                Name = p.Name,
                Description = p.Description,
                Tasks = p.Tasks
                    .OrderByDescending(t => t.CreatedAt)
                    .Select(t => new ProjectTaskDto
                    {
                        Id = t.Id,
                        Title = t.Title,
                        IsDone = t.IsDone,
                        CreatedAt = t.CreatedAt,
                        CompletedAt = t.CompletedAt,
                    })
                    .ToList(),
            })
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<AddProjectTaskResult?> AddTaskAsync(string userId, string projectId, string title, CancellationToken cancellationToken = default)
    {
        UserTierProfile? profile = await GetTierProfileAsync(userId, cancellationToken);
        if (profile is null)
        {
            return null;
        }

        Project? project = await _db.Projects
            .FirstOrDefaultAsync(p => p.Id == projectId && p.OwnerUserId == userId, cancellationToken);

        if (project is null)
        {
            return null;
        }

        var existingTaskCount = await _db.ProjectTasks
            .AsNoTracking()
            .CountAsync(t => t.ProjectId == projectId, cancellationToken);

        if (existingTaskCount >= profile.MaxTasksPerProject)
        {
            return null;
        }

        DateTime now = DateTime.UtcNow;
        var task = new ProjectTask
        {
            Id = Guid.CreateVersion7().ToString(),
            ProjectId = project.Id,
            Title = title.Trim(),
            IsDone = false,
            CreatedAt = now,
            CompletedAt = null,
        };

        project.UpdatedAt = now;
        _db.ProjectTasks.Add(task);
        await _db.SaveChangesAsync(cancellationToken);

        return new AddProjectTaskResult
        {
            Id = task.Id,
            ProjectId = task.ProjectId,
            Title = task.Title,
            IsDone = task.IsDone,
            CreatedAt = task.CreatedAt,
            CompletedAt = task.CompletedAt,
        };
    }
}
