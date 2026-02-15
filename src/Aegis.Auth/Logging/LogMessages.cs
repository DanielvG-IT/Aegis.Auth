using Microsoft.Extensions.Logging;

namespace Aegis.Auth.Logging
{
    /// <summary>
    /// Source-generated logging messages for high-performance structured logging.
    /// Following .NET best practices for library authors.
    /// </summary>
    internal static partial class LogMessages
    {
        // ═══════════════════════════════════════════════════════════════════════════════
        // Sign In Messages
        // ═══════════════════════════════════════════════════════════════════════════════

        [LoggerMessage(
            EventId = 1000,
            Level = LogLevel.Debug,
            Message = "SignIn attempt initiated for email sign-in")]
        internal static partial void SignInAttemptInitiated(this ILogger logger);

        [LoggerMessage(
            EventId = 1001,
            Level = LogLevel.Warning,
            Message = "SignIn attempt blocked: Email/Password authentication is disabled")]
        internal static partial void SignInFeatureDisabled(this ILogger logger);

        [LoggerMessage(
            EventId = 1002,
            Level = LogLevel.Warning,
            Message = "SignIn attempt failed: Email is missing")]
        internal static partial void SignInEmailMissing(this ILogger logger);

        [LoggerMessage(
            EventId = 1003,
            Level = LogLevel.Warning,
            Message = "SignIn attempt failed: Invalid email format")]
        internal static partial void SignInInvalidEmailFormat(this ILogger logger);

        [LoggerMessage(
            EventId = 1004,
            Level = LogLevel.Debug,
            Message = "SignIn database lookup completed for provided email")]
        internal static partial void SignInDatabaseLookupCompleted(this ILogger logger);

        [LoggerMessage(
            EventId = 1005,
            Level = LogLevel.Error,
            Message = "SignIn failed: Database lookup error for provided email")]
        internal static partial void SignInDatabaseLookupError(this ILogger logger, Exception exception);

        [LoggerMessage(
            EventId = 1006,
            Level = LogLevel.Warning,
            Message = "SignIn failed: User not found for provided email. Performing timing-safe hash")]
        internal static partial void SignInUserNotFound(this ILogger logger);

        [LoggerMessage(
            EventId = 1007,
            Level = LogLevel.Warning,
            Message = "SignIn failed: No credential account found for user {UserId}")]
        internal static partial void SignInNoCredentialAccount(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1008,
            Level = LogLevel.Warning,
            Message = "SignIn failed: Password hash missing for user {UserId}")]
        internal static partial void SignInPasswordHashMissing(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1009,
            Level = LogLevel.Warning,
            Message = "SignIn failed: Invalid password for user {UserId}")]
        internal static partial void SignInInvalidPassword(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1010,
            Level = LogLevel.Debug,
            Message = "Password verified successfully for user {UserId}")]
        internal static partial void SignInPasswordVerified(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1011,
            Level = LogLevel.Information,
            Message = "SignIn blocked: Email not verified for user {UserId}")]
        internal static partial void SignInEmailNotVerified(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1012,
            Level = LogLevel.Error,
            Message = "SignIn failed: Email verification required but SendVerificationEmail is not configured for user {UserId}")]
        internal static partial void SignInEmailVerificationNotConfigured(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1013,
            Level = LogLevel.Information,
            Message = "Sending verification email to user {UserId}")]
        internal static partial void SignInSendingVerificationEmail(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1014,
            Level = LogLevel.Information,
            Message = "Verification email sent successfully to user {UserId}")]
        internal static partial void SignInVerificationEmailSent(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1015,
            Level = LogLevel.Warning,
            Message = "SignIn blocked: Email not verified and SendOnSignIn is disabled for user {UserId}")]
        internal static partial void SignInVerificationDisabled(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1016,
            Level = LogLevel.Debug,
            Message = "Creating session for user {UserId}")]
        internal static partial void SignInCreatingSession(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1017,
            Level = LogLevel.Warning,
            Message = "SignIn failed: Failed to create session for user {UserId}")]
        internal static partial void SignInSessionCreationFailed(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 1018,
            Level = LogLevel.Information,
            Message = "SignIn successful for user {UserId}")]
        internal static partial void SignInSuccessful(this ILogger logger, string userId);

        // ═══════════════════════════════════════════════════════════════════════════════
        // Sign Up Messages
        // ═══════════════════════════════════════════════════════════════════════════════

        [LoggerMessage(
            EventId = 2000,
            Level = LogLevel.Debug,
            Message = "SignUp attempt initiated for email sign-up")]
        internal static partial void SignUpAttemptInitiated(this ILogger logger);

        [LoggerMessage(
            EventId = 2001,
            Level = LogLevel.Warning,
            Message = "SignUp attempt blocked: Email/Password authentication is disabled")]
        internal static partial void SignUpFeatureDisabled(this ILogger logger);

        [LoggerMessage(
            EventId = 2002,
            Level = LogLevel.Warning,
            Message = "SignUp attempt failed: Email or password is missing")]
        internal static partial void SignUpInputMissing(this ILogger logger);

        [LoggerMessage(
          EventId = 2003,
          Level = LogLevel.Warning,
          Message = "SignUp attempt failed: Password is too short (minimum {MinLength} characters)")]
        internal static partial void SignUpPasswordTooShort(this ILogger logger, int minLength);

        [LoggerMessage(
          EventId = 2004,
          Level = LogLevel.Warning,
          Message = "SignUp attempt failed: Password is too short (minimum {MinLength} characters)")]
        internal static partial void SignUpPasswordTooLong(this ILogger logger, int minLength);

        [LoggerMessage(
            EventId = 2005,
            Level = LogLevel.Warning,
            Message = "SignUp attempt failed: Custom password validation failed")]
        internal static partial void SignUpPasswordValidationFailed(this ILogger logger);

        [LoggerMessage(
            EventId = 2006,
            Level = LogLevel.Warning,
            Message = "SignUp attempt failed: Invalid email format")]
        internal static partial void SignUpInvalidEmailFormat(this ILogger logger);

        [LoggerMessage(
            EventId = 2007,
            Level = LogLevel.Warning,
            Message = "SignUp attempt failed: Email already registered")]
        internal static partial void SignUpEmailAlreadyExists(this ILogger logger);

        [LoggerMessage(
            EventId = 2008,
            Level = LogLevel.Information,
            Message = "Creating new user account for email sign-up")]
        internal static partial void SignUpCreatingUser(this ILogger logger);

        [LoggerMessage(
            EventId = 2009,
            Level = LogLevel.Information,
            Message = "SignUp successful: User {UserId} created")]
        internal static partial void SignUpSuccessful(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 2010,
            Level = LogLevel.Error,
            Message = "SignUp failed: Database save error")]
        internal static partial void SignUpDatabaseSaveError(this ILogger logger, Exception exception);

        [LoggerMessage(
            EventId = 2011,
            Level = LogLevel.Warning,
            Message = "SignUp failed: Duplicate key constraint violation detected")]
        internal static partial void SignUpDuplicateKeyError(this ILogger logger, Exception exception);

        // ═══════════════════════════════════════════════════════════════════════════════
        // Session Messages
        // ═══════════════════════════════════════════════════════════════════════════════

        [LoggerMessage(
            EventId = 3000,
            Level = LogLevel.Debug,
            Message = "Creating new session for user {UserId}")]
        internal static partial void SessionCreating(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 3001,
            Level = LogLevel.Information,
            Message = "Session {SessionId} created successfully for user {UserId}")]
        internal static partial void SessionCreated(this ILogger logger, string sessionId, string userId);

        [LoggerMessage(
            EventId = 3002,
            Level = LogLevel.Error,
            Message = "Failed to create session for user {UserId}")]
        internal static partial void SessionCreationFailed(this ILogger logger, string userId, Exception exception);

        [LoggerMessage(
            EventId = 3003,
            Level = LogLevel.Debug,
            Message = "Validating session {SessionId}")]
        internal static partial void SessionValidating(this ILogger logger, string sessionId);

        [LoggerMessage(
            EventId = 3004,
            Level = LogLevel.Warning,
            Message = "Session {SessionId} validation failed: Session expired")]
        internal static partial void SessionExpired(this ILogger logger, string sessionId);

        [LoggerMessage(
            EventId = 3005,
            Level = LogLevel.Warning,
            Message = "Session {SessionId} validation failed: Session not found")]
        internal static partial void SessionNotFound(this ILogger logger, string sessionId);

        [LoggerMessage(
            EventId = 3006,
            Level = LogLevel.Debug,
            Message = "Revoking session {Token}")]
        internal static partial void SessionRevoking(this ILogger logger, string token);

        [LoggerMessage(
            EventId = 3007,
            Level = LogLevel.Information,
            Message = "Session {Token} revoked successfully for user {UserId}")]
        internal static partial void SessionRevoked(this ILogger logger, string token, string userId);

        [LoggerMessage(
            EventId = 3008,
            Level = LogLevel.Error,
            Message = "Failed to revoke session {Token}")]
        internal static partial void SessionRevocationFailed(this ILogger logger, string token, Exception exception);

        [LoggerMessage(
            EventId = 3009,
            Level = LogLevel.Debug,
            Message = "Revoking all sessions for user {UserId}")]
        internal static partial void SessionRevokingAll(this ILogger logger, string userId);

        [LoggerMessage(
            EventId = 3010,
            Level = LogLevel.Information,
            Message = "All sessions revoked for user {UserId}")]
        internal static partial void SessionRevokedAll(this ILogger logger, string userId);

        // ═══════════════════════════════════════════════════════════════════════════════
        // Sign Out Messages
        // ═══════════════════════════════════════════════════════════════════════════════

        [LoggerMessage(
            EventId = 4000,
            Level = LogLevel.Debug,
            Message = "SignOut attempt initiated")]
        internal static partial void SignOutAttemptInitiated(this ILogger logger);

        [LoggerMessage(
            EventId = 4001,
            Level = LogLevel.Warning,
            Message = "SignOut failed: No session token found in request")]
        internal static partial void SignOutNoToken(this ILogger logger);

        [LoggerMessage(
            EventId = 4002,
            Level = LogLevel.Warning,
            Message = "SignOut failed: Session not found for token {Token}")]
        internal static partial void SignOutSessionNotFound(this ILogger logger, string token);

        [LoggerMessage(
            EventId = 4003,
            Level = LogLevel.Error,
            Message = "SignOut failed: Session revocation failed for token {Token}")]
        internal static partial void SignOutRevocationFailed(this ILogger logger, string token);

        [LoggerMessage(
            EventId = 4004,
            Level = LogLevel.Information,
            Message = "SignOut successful for user {UserId}")]
        internal static partial void SignOutSuccessful(this ILogger logger, string userId);
    }
}
