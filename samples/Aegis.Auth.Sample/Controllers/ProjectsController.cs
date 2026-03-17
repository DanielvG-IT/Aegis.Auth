using Aegis.Auth.Infrastructure.Cookies;
using Aegis.Auth.Sample.Data;
using Aegis.Auth.Sample.Services;

using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Controllers;

[ApiController]
[Route("api/projects")]
public sealed class ProjectsController(SampleAuthDbContext context, SessionCookieHandler cookieHandler, IProjectWorkspaceService workspaceService) : ControllerBase
{
  private readonly SampleAuthDbContext _context = context;
  private readonly SessionCookieHandler _cookieHandler = cookieHandler;
  private readonly IProjectWorkspaceService _workspaceService = workspaceService;

  [HttpGet("my")]
  public async Task<IActionResult> GetMyProjects(CancellationToken cancellationToken)
  {
    var userId = await ResolveUserIdAsync(cancellationToken);
    if (userId is null)
    {
      return Unauthorized(new { message = "Sign in first to access your projects." });
    }

    var tierProfile = await _workspaceService.GetTierProfileAsync(userId, cancellationToken);
    if (tierProfile is null)
    {
      return Unauthorized(new { message = "Authenticated user was not found." });
    }

    var projects = await _workspaceService.GetProjectsForUserAsync(userId, cancellationToken);

    return Ok(new
    {
      user = new
      {
        tierProfile.UserId,
        tierProfile.IsSpecial,
        tierProfile.Tier,
        tierProfile.MaxProjects,
        tierProfile.MaxTasksPerProject,
      },
      projects
    });
  }

  [HttpGet("my/workspace")]
  public async Task<IActionResult> GetMyWorkspace(CancellationToken cancellationToken)
  {
    var userId = await ResolveUserIdAsync(cancellationToken);
    if (userId is null)
    {
      return Unauthorized(new { message = "Sign in first to access workspace details." });
    }

    var tierProfile = await _workspaceService.GetTierProfileAsync(userId, cancellationToken);
    if (tierProfile is null)
    {
      return Unauthorized(new { message = "Authenticated user was not found." });
    }

    var projectCount = await _context.Projects
        .AsNoTracking()
        .CountAsync(p => p.OwnerUserId == userId, cancellationToken);

    return Ok(new
    {
      tierProfile.UserId,
      tierProfile.IsSpecial,
      tierProfile.Tier,
      limits = new
      {
        maxProjects = tierProfile.MaxProjects,
        maxTasksPerProject = tierProfile.MaxTasksPerProject,
      },
      usage = new
      {
        currentProjects = projectCount,
        remainingProjects = Math.Max(0, tierProfile.MaxProjects - projectCount),
      },
      benefit = tierProfile.IsSpecial
            ? "Priority limits and premium project capacity enabled"
            : "Standard limits enabled"
    });
  }

  [HttpPost]
  public async Task<IActionResult> CreateProject([FromBody] CreateProjectRequest request, CancellationToken cancellationToken)
  {
    var userId = await ResolveUserIdAsync(cancellationToken);
    if (userId is null)
    {
      return Unauthorized(new { message = "Sign in first to create projects." });
    }

    if (string.IsNullOrWhiteSpace(request.Name))
    {
      return BadRequest(new { message = "Project name is required." });
    }

    var createdProject = await _workspaceService.CreateProjectAsync(
        userId,
        request.Name,
        request.Description,
        cancellationToken);

    if (createdProject is null)
    {
      return BadRequest(new
      {
        message = "Project could not be created. You may have reached your tier project limit."
      });
    }

    return CreatedAtAction(nameof(GetProjectTasks), new { projectId = createdProject.Id }, new
    {
      createdProject.Id,
      createdProject.Name,
      createdProject.Description,
      createdProject.CreatedAt,
      createdProject.UpdatedAt,
    });
  }

  [HttpGet("{projectId}/tasks")]
  public async Task<IActionResult> GetProjectTasks(string projectId, CancellationToken cancellationToken)
  {
    var userId = await ResolveUserIdAsync(cancellationToken);
    if (userId is null)
    {
      return Unauthorized(new { message = "Sign in first to access project tasks." });
    }

    var project = await _workspaceService.GetProjectTasksAsync(userId, projectId, cancellationToken);

    if (project is null)
    {
      return NotFound(new { message = "Project not found." });
    }

    return Ok(project);
  }

  [HttpPost("{projectId}/tasks")]
  public async Task<IActionResult> AddTask(string projectId, [FromBody] AddTaskRequest request, CancellationToken cancellationToken)
  {
    var userId = await ResolveUserIdAsync(cancellationToken);
    if (userId is null)
    {
      return Unauthorized(new { message = "Sign in first to add tasks." });
    }

    if (string.IsNullOrWhiteSpace(request.Title))
    {
      return BadRequest(new { message = "Task title is required." });
    }

    var createdTask = await _workspaceService.AddTaskAsync(userId, projectId, request.Title, cancellationToken);
    if (createdTask is null)
    {
      return BadRequest(new
      {
        message = "Task could not be added. Project may not exist or task limit may have been reached for your tier."
      });
    }

    return Ok(new
    {
      createdTask.Id,
      createdTask.ProjectId,
      createdTask.Title,
      createdTask.IsDone,
      createdTask.CreatedAt,
      createdTask.CompletedAt,
    });
  }

  private async Task<string?> ResolveUserIdAsync(CancellationToken cancellationToken)
  {
    // Fast path: use verified session_data cookie when present.
    var userId = _cookieHandler.GetCookieCache(HttpContext)?.User.Id;
    if (string.IsNullOrWhiteSpace(userId) is false)
    {
      return userId;
    }

    var token = _cookieHandler.GetSessionToken(HttpContext);
    if (string.IsNullOrWhiteSpace(token))
    {
      return null;
    }

    var session = await _context.Sessions
        .AsNoTracking()
        .FirstOrDefaultAsync(s => s.Token == token, cancellationToken);

    if (session is null || session.ExpiresAt <= DateTime.UtcNow)
    {
      return null;
    }

    return session.UserId;
  }

  public sealed class CreateProjectRequest
  {
    [Required]
    [StringLength(120, MinimumLength = 1)]
    public required string Name { get; init; }

    [StringLength(500)]
    public string? Description { get; init; }
  }

  public sealed class AddTaskRequest
  {
    [Required]
    [StringLength(180, MinimumLength = 1)]
    public required string Title { get; init; }
  }
}
