using Aegis.Auth.Features.EmailVerification;
using Aegis.Auth.Http.Features.PasswordReset;
using Aegis.Auth.Http.Features.SignIn;
using Aegis.Auth.Http.Features.SignOut;
using Aegis.Auth.Http.Features.SignUp;
using Aegis.Auth.Options;
using Aegis.Auth.Plugins;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Aegis.Auth.Http.Extensions;

public sealed class AegisAuthEndpointMapOptions
{
    public string BasePath { get; set; } = "/api/auth";
    public string TagName { get; set; } = "Aegis Auth";

    // Allow consumers to hide endpoints from the route table entirely.
    public bool MapSignOut { get; set; } = true;
    public bool MapEmailSignIn { get; set; } = true;
    public bool MapEmailSignUp { get; set; } = true;
    public bool MapOAuthSignIn { get; set; } = true;
    public bool MapPasswordReset { get; set; } = true;

    // Maps the built-in email verification plugin.
    public bool MapEmailVerification { get; set; } = true;

    // true: derive defaults from AegisAuthOptions feature flags.
    // false: map strictly by Map* toggles above.
    public bool RespectConfiguration { get; set; } = true;
}

public static class AegisAuthEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapAegisAuthEndpoints(
                this IEndpointRouteBuilder endpoints,
                Action<AegisAuthEndpointMapOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var mapOptions = new AegisAuthEndpointMapOptions { RespectConfiguration = true };
        configure?.Invoke(mapOptions);

        AegisAuthOptions authOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<AegisAuthOptions>>().Value;
        RouteGroupBuilder group = endpoints.MapGroup(mapOptions.BasePath).WithTags(mapOptions.TagName);

        if (mapOptions.MapSignOut)
        {
            group.MapSignOut();
        }

        var canMapOAuth = mapOptions.MapOAuthSignIn;
        if (canMapOAuth)
        {
            if (mapOptions.RespectConfiguration && (authOptions.OAuth.Enabled is false || Aegis.Auth.Features.OAuth.OAuthProviderCatalog.HasEnabledProviders(authOptions.OAuth) is false))
            {
                canMapOAuth = false;
            }

            if (canMapOAuth)
            {
                group.MapOAuth();
            }
        }

        var emailAndPasswordEnabled = mapOptions.RespectConfiguration is false || authOptions.EmailAndPassword.Enabled;

        var canMapEmail = mapOptions.MapEmailSignIn || mapOptions.MapEmailSignUp;
        if (canMapEmail && emailAndPasswordEnabled)
        {
            if (mapOptions.MapEmailSignIn)
            {
                group.MapSignInEmail();
            }

            var canMapEmailSignUp = mapOptions.MapEmailSignUp;
            if (mapOptions.RespectConfiguration)
            {
                canMapEmailSignUp = canMapEmailSignUp && authOptions.EmailAndPassword.DisableSignUp is false;
            }

            if (canMapEmailSignUp)
            {
                group.MapSignUpEmail();
            }
        }

        // Token endpoints are only useful when the app can deliver the token.
        var canMapPasswordReset = mapOptions.MapPasswordReset && emailAndPasswordEnabled;
        if (mapOptions.RespectConfiguration)
        {
            canMapPasswordReset = canMapPasswordReset && authOptions.EmailAndPassword.SendResetPassword is not null;
        }

        if (canMapPasswordReset)
        {
            group.MapPasswordReset();
        }

        MapPluginEndpoints(endpoints, group, mapOptions, authOptions);

        return endpoints;
    }

    /// <summary>
    /// Maps each plugin into its own sub-group of the Aegis group, so its routes can be told apart
    /// and checked against the core routes and every earlier plugin.
    /// </summary>
    private static void MapPluginEndpoints(
        IEndpointRouteBuilder endpoints,
        RouteGroupBuilder group,
        AegisAuthEndpointMapOptions mapOptions,
        AegisAuthOptions authOptions)
    {
        AegisPluginRegistry registry = endpoints.ServiceProvider.GetRequiredService<AegisPluginRegistry>();

        var mappedRoutes = new Dictionary<string, List<(string Methods, string Owner)>>(StringComparer.OrdinalIgnoreCase);
        foreach (RouteEndpoint endpoint in GetRouteEndpoints(group))
        {
            AddRoute(mappedRoutes, endpoint, "Aegis core");
        }

        foreach (AegisPlugin plugin in registry.Plugins)
        {
            if (plugin.Id == EmailVerificationPlugin.PluginId && mapOptions.MapEmailVerification is false)
            {
                continue;
            }

            if (mapOptions.RespectConfiguration && plugin.ShouldMapEndpoints(authOptions) is false)
            {
                continue;
            }

            RouteGroupBuilder pluginGroup = group.MapGroup(string.Empty);
            plugin.MapEndpoints(pluginGroup);

            foreach (RouteEndpoint endpoint in GetRouteEndpoints(pluginGroup))
            {
                AddRoute(mappedRoutes, endpoint, $"plugin '{plugin.Id}'");
            }
        }
    }

    private static IEnumerable<RouteEndpoint> GetRouteEndpoints(IEndpointRouteBuilder builder) =>
        builder.DataSources.SelectMany(source => source.Endpoints).OfType<RouteEndpoint>();

    private static void AddRoute(
        Dictionary<string, List<(string Methods, string Owner)>> mappedRoutes,
        RouteEndpoint endpoint,
        string owner)
    {
        var path = NormalizeRoute(endpoint.RoutePattern);
        IReadOnlyList<string>? methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;
        var methodList = methods is null || methods.Count == 0 ? "*" : string.Join(",", methods);

        if (mappedRoutes.TryGetValue(path, out List<(string Methods, string Owner)>? existing) is false)
        {
            mappedRoutes[path] = [(methodList, owner)];
            return;
        }

        foreach ((var existingMethods, var existingOwner) in existing)
        {
            if (MethodsOverlap(existingMethods, methodList))
            {
                throw new InvalidOperationException(
                    $"Aegis route conflict: {owner} maps {methodList} '{endpoint.RoutePattern.RawText}', which {existingOwner} already maps ({existingMethods}).");
            }
        }

        existing.Add((methodList, owner));
    }

    private static bool MethodsOverlap(string left, string right) =>
        left == "*" || right == "*" || left.Split(',').Intersect(right.Split(','), StringComparer.OrdinalIgnoreCase).Any();

    // Parameter names don't matter for matching, so '/{id}' and '/{userId}' collide.
    private static string NormalizeRoute(RoutePattern pattern) =>
        "/" + string.Join("/", pattern.PathSegments.Select(segment => string.Concat(segment.Parts.Select(part => part switch
        {
            RoutePatternLiteralPart literal => literal.Content,
            RoutePatternSeparatorPart separator => separator.Content,
            _ => "{}",
        }))));
}
