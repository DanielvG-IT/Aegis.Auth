using Aegis.Auth.Abstractions;
using Aegis.Auth.Entities;
using Aegis.Auth.Extensions;
using Aegis.Auth.Http.Extensions;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;

namespace Aegis.Auth.TestPlugins.Workspaces;

public sealed record CreateWorkspaceRequest(string Name, string Slug);

public sealed record SetActiveWorkspaceRequest(string WorkspaceId);

public sealed record ActiveWorkspaceResponse(string? WorkspaceId, string? Role);

internal static class WorkspaceEndpoints
{
    public static void MapWorkspaces(this RouteGroupBuilder group)
    {
        RouteGroupBuilder workspaces = group.MapGroup("/workspace").RequireAegisAuth();
        workspaces.MapPost("/create", CreateAsync);
        workspaces.MapPost("/set-active", SetActiveAsync);
        workspaces.MapGet("/active", GetActiveAsync);
    }

    private static async Task<IResult> CreateAsync(
        HttpContext httpContext,
        IAuthDbContext authDb,
        WorkspaceOptions options,
        TimeProvider time,
        CreateWorkspaceRequest request,
        CancellationToken ct)
    {
        AegisAuthContext auth = httpContext.GetAegisAuthContext()!;
        DbContext db = authDb.GetDbContext();

        if (await db.Set<WorkspaceMember>().CountAsync(m => m.UserId == auth.UserId, ct) >= options.WorkspaceLimit)
        {
            return AegisResults.Problem(httpContext, WorkspacesPlugin.LimitReached, "Workspace limit reached.");
        }

        var slug = request.Slug.Trim().ToLowerInvariant();
        if (await db.Set<Workspace>().AnyAsync(w => w.Slug == slug, ct))
        {
            return AegisResults.Problem(httpContext, WorkspacesPlugin.SlugTaken, "Slug is taken.");
        }

        DateTime now = time.GetUtcNow().UtcDateTime;
        var workspace = new Workspace { Id = Guid.NewGuid().ToString(), Name = request.Name, Slug = slug, CreatedAt = now };
        db.Add(workspace);
        db.Add(new WorkspaceMember { Id = Guid.NewGuid().ToString(), WorkspaceId = workspace.Id, UserId = auth.UserId, Role = "owner", CreatedAt = now });

        // The creator's session switches to the new workspace in the same save.
        Session? session = await authDb.Sessions.FindAsync([auth.SessionId], ct);
        if (session is not null)
        {
            db.Entry(session).Property(WorkspacesPlugin.ActiveWorkspaceIdProperty).CurrentValue = workspace.Id;
        }

        await db.SaveChangesAsync(ct);
        return Results.Ok(new { workspace.Id, workspace.Slug });
    }

    private static async Task<IResult> SetActiveAsync(
        HttpContext httpContext,
        IAuthDbContext authDb,
        SetActiveWorkspaceRequest request,
        CancellationToken ct)
    {
        AegisAuthContext auth = httpContext.GetAegisAuthContext()!;
        DbContext db = authDb.GetDbContext();

        // Never trust the id in the body: the caller must be a member, checked against the database.
        var isMember = await db.Set<WorkspaceMember>()
            .AnyAsync(m => m.WorkspaceId == request.WorkspaceId && m.UserId == auth.UserId, ct);
        if (isMember is false)
        {
            return AegisResults.Problem(httpContext, WorkspacesPlugin.NotMember, "Not a member of this workspace.");
        }

        Session? session = await authDb.Sessions.FindAsync([auth.SessionId], ct);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        db.Entry(session).Property(WorkspacesPlugin.ActiveWorkspaceIdProperty).CurrentValue = request.WorkspaceId;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> GetActiveAsync(HttpContext httpContext, IAuthDbContext authDb, CancellationToken ct)
    {
        AegisAuthContext auth = httpContext.GetAegisAuthContext()!;
        DbContext db = authDb.GetDbContext();

        var activeId = await authDb.Sessions
            .Where(s => s.Id == auth.SessionId)
            .Select(s => EF.Property<string?>(s, WorkspacesPlugin.ActiveWorkspaceIdProperty))
            .FirstOrDefaultAsync(ct);

        // Membership can be revoked after the workspace was made active, so re-check it on every read.
        var role = activeId is null
            ? null
            : await db.Set<WorkspaceMember>()
                .Where(m => m.WorkspaceId == activeId && m.UserId == auth.UserId)
                .Select(m => m.Role)
                .FirstOrDefaultAsync(ct);

        return Results.Ok(role is null ? new ActiveWorkspaceResponse(null, null) : new ActiveWorkspaceResponse(activeId, role));
    }
}
