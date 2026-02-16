namespace Aegis.Auth.Constants
{
    public static class AuthErrors
    {
        // 🛠️ System & Configuration
        public static class System
        {
            public const string InternalError = "INTERNAL_ERROR";
            public const string FeatureDisabled = "FEATURE_DISABLED";
            public const string ProviderNotFound = "PROVIDER_NOT_FOUND";
            public const string VerificationEmailNotEnabled = "VERIFICATION_EMAIL_NOT_ENABLED";
            public const string FailedToCreateSession = "FAILED_TO_CREATE_SESSION";
        }

        // 📝 Input Validation
        public static class Validation
        {
            public const string InvalidInput = "INVALID_INPUT";
            public const string EmailRequired = "EMAIL_REQUIRED";
            public const string PasswordTooShort = "PASSWORD_TOO_SHORT";
            public const string PasswordTooLong = "PASSWORD_TOO_LONG";
        }

        // 🔐 Identity & Access
        public static class Identity
        {
            public const string InvalidCredentials = "INVALID_CREDENTIALS";
            public const string InvalidEmailOrPassword = "INVALID_EMAIL_OR_PASSWORD";
            public const string EmailNotVerified = "EMAIL_NOT_VERIFIED";
            public const string UserAlreadyExists = "USER_ALREADY_EXISTS";
        }

        // 🔑 Session
        public static class Session
        {
            public const string SessionNotFound = "SESSION_NOT_FOUND";
            public const string SessionExpired = "SESSION_EXPIRED";
        }
    }
}
