using Aegis.Auth.Abstractions;
using Aegis.Auth.Extensions;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Aegis.Auth.Http.Extensions;

public static class AegisAuthProtectionExtensions
{
    public static RouteGroupBuilder RequireAegisAuth(this RouteGroupBuilder group)
    {
        ArgumentNullException.ThrowIfNull(group);

        group.AddEndpointFilter<AegisAuthRequiredEndpointFilter>();
        return group;
    }

    public static RouteHandlerBuilder RequireAegisAuth(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.AddEndpointFilter<AegisAuthRequiredEndpointFilter>();
        return builder;
    }

    private sealed class AegisAuthRequiredEndpointFilter : IEndpointFilter
    {
        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            if (context.HttpContext.RequestServices.GetService(typeof(IAegisAuthContextAccessor)) is not IAegisAuthContextAccessor accessor)
            {
                return Results.Problem(
                    title: "Server Misconfiguration",
                    detail: "Aegis auth services are not registered.",
                    statusCode: StatusCodes.Status500InternalServerError,
                    type: "https://httpstatuses.com/500",
                    instance: context.HttpContext.Request.Path);
            }

            AegisAuthContext? authContext = await accessor.GetCurrentAsync(context.HttpContext, context.HttpContext.RequestAborted);
            if (authContext is null)
            {
                return Results.Problem(
                    title: "Unauthorized",
                    detail: "Authentication is required to access this resource.",
                    statusCode: StatusCodes.Status401Unauthorized,
                    type: "https://httpstatuses.com/401",
                    instance: context.HttpContext.Request.Path);
            }

            context.HttpContext.SetAegisAuthContext(authContext);
            return await next(context);
        }
    }
}
