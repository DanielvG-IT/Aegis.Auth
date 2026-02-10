using Aegis.Auth.Entities;

using Microsoft.AspNetCore.Http;

namespace Aegis.Auth.Abstractions
{
  /// <summary>
  /// Shared service for creating and managing user sessions.
  /// Used by both core authentication and feature packages (Passkeys, TOTP, OAuth, etc.)
  /// to maintain consistent session handling across all sign-in methods.
  /// </summary>
  public interface IAegisSessionService
  {
    /// <summary>
    /// Creates a new session for a user and sets the authentication cookie.
    /// </summary>
    /// <param name="user">The authenticated user.</param>
    /// <param name="context">The HTTP context for setting cookies.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created session.</returns>
    Task<Session> CreateSessionAsync(User user, HttpContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates a session and clears the authentication cookie.
    /// </summary>
    /// <param name="sessionId">The session ID to invalidate.</param>
    /// <param name="context">The HTTP context for clearing cookies.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task InvalidateSessionAsync(string sessionId, HttpContext context, CancellationToken cancellationToken = default);
  }
}
