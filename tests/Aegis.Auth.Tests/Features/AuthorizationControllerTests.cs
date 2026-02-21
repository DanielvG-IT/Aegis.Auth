using System.Net;
using System.Net.Http.Json;

using Microsoft.AspNetCore.Mvc.Testing;

namespace Aegis.Auth.Tests.Features;

public sealed class AuthorizationControllerTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory = factory;

    [Fact]
    public async Task SignOut_RequiresAuthorization()
    {
        // Arrange
        HttpClient client = _factory.CreateClient();

        // Act
        HttpResponseMessage response = await client.PostAsync("/api/auth/sign-out", null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SignOut_WithValidSessionCookie_ReturnsOk()
    {
        HttpClient client = _factory.CreateClient();

        var signInResponse = await client.PostAsJsonAsync("/api/auth/sign-in/email", new
        {
            Email = "test@example.com",
            Password = "Password123!",
            RememberMe = true
        });

        Assert.Equal(HttpStatusCode.OK, signInResponse.StatusCode);

        HttpResponseMessage signOutResponse = await client.PostAsync("/api/auth/sign-out", null);

        Assert.Equal(HttpStatusCode.OK, signOutResponse.StatusCode);
    }
}
