namespace Aegis.Auth
{
    // For actions that return nothing (void)
    public class Result
    {
        public bool IsSuccess { get; }
        public string? ErrorCode { get; }
        public string? Message { get; }

        private Result(bool success, string? errorCode, string? message)
        {
            IsSuccess = success;
            ErrorCode = errorCode;
            Message = message;
        }

        public static Result Success()
        {
            return new(true, null, null);
        }

        public static Result Failure(string code, string msg)
        {
            return new(false, code, msg);
        }
    }

    // For actions that return data
    public class Result<T>
    {
        public bool IsSuccess { get; }
        public T? Value { get; }
        public string? ErrorCode { get; }
        public string? Message { get; }

        private Result(bool success, T? value, string? errorCode, string? message)
        {
            IsSuccess = success;
            Value = value;
            ErrorCode = errorCode;
            Message = message;
        }

        public static Result<T> Success(T value)
        {
            return new(true, value, null, null);
        }

        public static Result<T> Failure(string code, string msg)
        {
            return new(false, default, code, msg);
        }

        // Helper to "downgrade" to a plain Result
        public Result ToResult()
        {
            return IsSuccess
            ? Result.Success()
            : Result.Failure(ErrorCode ?? "UNKNOWN_ERROR", Message ?? "An unknown error occurred");
        }

        // The "Magic" implicit operator
        public static implicit operator Result<T>(T value) => Success(value);
    }
}
