using System.ComponentModel.DataAnnotations;

using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;
using Aegis.Auth.Sample.Data;
using Aegis.Auth.Sample.Services;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.Sample.Controllers;

[ApiController]
[Route("api/projects")]
[AegisAuthorize]
public sealed class ProjectsController(SampleAuthDbContext context, IProjectWorkspaceService workspaceService) : ControllerBase
{
    private readonly SampleAuthDbContext _context = context;
    private readonly IProjectWorkspaceService _workspaceService = workspaceService;

    [HttpGet("my")]
    public async Task<IActionResult> GetMyProjects(CancellationToken cancellationToken)
    {
        var userId = GetRequiredUserId();

        UserTierProfile? tierProfile = await _workspaceService.GetTierProfileAsync(userId, cancellationToken);
        if (tierProfile is null)
        {
            return Unauthorized(new { message = "Authenticated user was not found." });
        }

        List<ProjectSummaryDto> projects = await _workspaceService.GetProjectsForUserAsync(userId, cancellationToken);

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
        var userId = GetRequiredUserId();

        UserTierProfile? tierProfile = await _workspaceService.GetTierProfileAsync(userId, cancellationToken);
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
        var userId = GetRequiredUserId();

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return BadRequest(new { message = "Project name is required." });
        }

        CreateProjectResult? createdProject = await _workspaceService.CreateProjectAsync(
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
        var userId = GetRequiredUserId();

        ProjectTasksDto? project = await _workspaceService.GetProjectTasksAsync(userId, projectId, cancellationToken);

        if (project is null)
        {
            return NotFound(new { message = "Project not found." });
        }

        return Ok(project);
    }

    [HttpPost("{projectId}/tasks")]
    public async Task<IActionResult> AddTask(string projectId, [FromBody] AddTaskRequest request, CancellationToken cancellationToken)
    {
        var userId = GetRequiredUserId();

        if (string.IsNullOrWhiteSpace(request.Title))
        {
            return BadRequest(new { message = "Task title is required." });
        }

        AddProjectTaskResult? createdTask = await _workspaceService.AddTaskAsync(userId, projectId, request.Title, cancellationToken);
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

    private string GetRequiredUserId()
    {
        AegisAuthContext? authContext = HttpContext.GetAegisAuthContext();
        if (authContext is null || string.IsNullOrWhiteSpace(authContext.UserId))
            throw new InvalidOperationException("Aegis auth context is unavailable. Ensure [AegisAuthorize] is applied.");

        return authContext.UserId;
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
