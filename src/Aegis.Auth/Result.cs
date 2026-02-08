namespace Aegis.Auth
{
    // For actions that return nothing (void)
    public class Result
    {
        public bool IsSuccess { get; }
        public string? ErrorCode { get; }
        public string? Message { get; }

        protected Result(bool success, string? errorCode, string? message)
        {
            IsSuccess = success;
            ErrorCode = errorCode;
            Message = message;
        }

        public static Result Success() => new(true, null, null);
        public static Result Failure(string code, string msg) => new(false, code, msg);
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

        public static Result<T> Success(T value) => new(true, value, null, null);
        public static Result<T> Failure(string code, string msg) => new(false, default, code, msg);

        // Helper to "downgrade" to a plain Result
        public Result ToResult() => IsSuccess
            ? Result.Success()
            : Result.Failure(ErrorCode!, Message!);

        // The "Magic" implicit operator
        public static implicit operator Result<T>(T value) => Success(value);
    }
}