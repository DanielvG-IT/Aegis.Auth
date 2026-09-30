using Aegis.Auth.Abstractions;
using Aegis.Auth.Constants;
using Aegis.Auth.Extensions;
using Aegis.Auth.Http.Extensions;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Aegis.Auth.Organizations;

public sealed record CreateOrganizationRequest(string Name, string Slug, string? Logo = null, string? Metadata = null);

public sealed record UpdateOrganizationRequest(string? OrganizationId, string? Name = null, string? Slug = null, string? Logo = null, string? Metadata = null);

public sealed record OrganizationIdRequest(string? OrganizationId);

public sealed record SetActiveOrganizationRequest(string? OrganizationId);

public sealed record AddMemberRequest(string? OrganizationId, string UserId, string Role);

public sealed record RemoveMemberRequest(string? OrganizationId, string MemberId);

public sealed record UpdateMemberRoleRequest(string? OrganizationId, string MemberId, string Role);

public sealed record CheckSlugResponse(bool Available);

internal static class OrganizationEndpoints
{
    public static void MapOrganizations(this RouteGroupBuilder group, OrganizationOptions options)
    {
        RouteGroupBuilder orgs = group.MapGroup("/organization").RequireAegisAuth();

        orgs.MapPost("/create", async (HttpContext http, IOrganizationService service, CreateOrganizationRequest request, CancellationToken ct) =>
        {
            AegisAuthContext auth = Auth(http);
            return ToHttp(http, await service.CreateAsync(auth.UserId, auth.SessionId, request.Name, request.Slug, request.Logo, request.Metadata, ct));
        });

        orgs.MapGet("/check-slug", async (IOrganizationService service, string slug, CancellationToken ct) =>
            Results.Ok(new CheckSlugResponse(await service.IsSlugAvailableAsync(slug, ct))));

        orgs.MapPost("/update", (HttpContext http, IOrganizationService service, UpdateOrganizationRequest request, CancellationToken ct) =>
            WithOrganizationAsync(http, service, request.OrganizationId, ct, async (auth, orgId) =>
                ToHttp(http, await service.UpdateAsync(auth.UserId, orgId, request.Name, request.Slug, request.Logo, request.Metadata, ct))));

        orgs.MapPost("/delete", (HttpContext http, IOrganizationService service, OrganizationIdRequest request, CancellationToken ct) =>
            WithOrganizationAsync(http, service, request.OrganizationId, ct, async (auth, orgId) =>
                ToHttp(http, await service.DeleteAsync(auth.UserId, orgId, ct))));

        orgs.MapGet("/list", async (HttpContext http, IOrganizationService service, CancellationToken ct) =>
            Results.Ok(await service.ListAsync(Auth(http).UserId, ct)));

        orgs.MapGet("/full", (HttpContext http, IOrganizationService service, string? organizationId, CancellationToken ct) =>
            WithOrganizationAsync(http, service, organizationId, ct, async (auth, orgId) =>
                ToHttp(http, await service.GetFullAsync(auth.UserId, orgId, ct))));

        orgs.MapPost("/set-active", async (HttpContext http, IOrganizationService service, SetActiveOrganizationRequest request, CancellationToken ct) =>
        {
            AegisAuthContext auth = Auth(http);
            return ToHttp(http, await service.SetActiveAsync(auth.UserId, auth.SessionId, request.OrganizationId, ct));
        });

        orgs.MapGet("/active-member", async (HttpContext http, IOrganizationService service, CancellationToken ct) =>
        {
            AegisAuthContext auth = Auth(http);
            Member? member = await service.GetActiveMemberAsync(auth.UserId, auth.SessionId, ct);
            return member is null
                ? AegisResults.Problem(http, OrganizationErrors.NoActiveOrganization, "No active organization.")
                : Results.Ok(member);
        });

        if (options.MapAddMemberEndpoint)
        {
            orgs.MapPost("/members/add", (HttpContext http, IOrganizationService service, AddMemberRequest request, CancellationToken ct) =>
                WithOrganizationAsync(http, service, request.OrganizationId, ct, async (auth, orgId) =>
                    ToHttp(http, await service.AddMemberAsync(auth.UserId, orgId, request.UserId, request.Role, ct))));
        }

        orgs.MapPost("/members/remove", (HttpContext http, IOrganizationService service, RemoveMemberRequest request, CancellationToken ct) =>
            WithOrganizationAsync(http, service, request.OrganizationId, ct, async (auth, orgId) =>
                ToHttp(http, await service.RemoveMemberAsync(auth.UserId, orgId, request.MemberId, ct))));

        orgs.MapPost("/members/update-role", (HttpContext http, IOrganizationService service, UpdateMemberRoleRequest request, CancellationToken ct) =>
            WithOrganizationAsync(http, service, request.OrganizationId, ct, async (auth, orgId) =>
                ToHttp(http, await service.UpdateMemberRoleAsync(auth.UserId, orgId, request.MemberId, request.Role, ct))));

        orgs.MapPost("/leave", (HttpContext http, IOrganizationService service, OrganizationIdRequest request, CancellationToken ct) =>
            WithOrganizationAsync(http, service, request.OrganizationId, ct, async (auth, orgId) =>
                ToHttp(http, await service.LeaveAsync(auth.UserId, orgId, ct))));
    }

    private static AegisAuthContext Auth(HttpContext http) => http.GetAegisAuthContext()!;

    /// <summary>Resolves the target organization: the explicit id, else the session's active organization.</summary>
    private static async Task<IResult> WithOrganizationAsync(
        HttpContext http, IOrganizationService service, string? organizationId, CancellationToken ct, Func<AegisAuthContext, string, Task<IResult>> action)
    {
        AegisAuthContext auth = Auth(http);
        organizationId ??= (await service.GetActiveMemberAsync(auth.UserId, auth.SessionId, ct))?.OrganizationId;
        return organizationId is null
            ? AegisResults.Problem(http, OrganizationErrors.NoActiveOrganization, "Pass organizationId or set an active organization.")
            : await action(auth, organizationId);
    }

    private static IResult ToHttp(HttpContext http, Result result) =>
        result.IsSuccess ? Results.NoContent() : AegisResults.Problem(http, result.ErrorCode, result.Message);

    private static IResult ToHttp<T>(HttpContext http, Result<T> result) =>
        result.IsSuccess ? Results.Ok(result.Value) : AegisResults.Problem(http, result.ErrorCode, result.Message);
}

public static class OrganizationPermissionExtensions
{
    /// <summary>
    /// Requires a signed-in user whose role in the session's <b>active</b> organization grants <paramref name="permission"/>
    /// (e.g. <c>project:create</c>). Checked against the database on every request.
    /// </summary>
    public static TBuilder RequireOrganizationPermission<TBuilder>(this TBuilder builder, string permission)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        builder.RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = AegisDefaults.AuthenticationScheme });
        builder.AddEndpointFilter(async (context, next) =>
        {
            HttpContext http = context.HttpContext;
            AegisAuthContext? auth = http.GetAegisAuthContext();
            if (auth is null)
            {
                return Results.Unauthorized();
            }

            IOrganizationService service = http.RequestServices.GetRequiredService<IOrganizationService>();
            return await service.HasPermissionAsync(auth.UserId, auth.SessionId, permission, http.RequestAborted)
                ? await next(context)
                : AegisResults.Problem(http, OrganizationErrors.Forbidden, $"Your role in the active organization does not grant '{permission}'.");
        });
        return builder;
    }
}
