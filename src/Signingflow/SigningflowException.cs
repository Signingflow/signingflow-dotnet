namespace Signingflow;

/// <summary>Every SDK error. Catch this to handle all of them.</summary>
public class SigningflowException : Exception
{
    public SigningflowException(string? message)
        : this(message, 0, null, "", "", "", "", "", "", "", null)
    {
    }

    public SigningflowException(
        string? message,
        int statusCode,
        int? grpcCode,
        string? traceCode,
        string? requestId,
        string? idempotencyKey,
        string? capability,
        string? resourceName,
        string? envelopeName,
        string? retryAfter,
        IReadOnlyList<FieldViolation>? fieldViolations)
        : base(message ?? "")
    {
        StatusCode = statusCode;
        GrpcCode = grpcCode;
        TraceCode = traceCode ?? "";
        RequestId = requestId ?? "";
        IdempotencyKey = idempotencyKey ?? "";
        Capability = capability ?? "";
        ResourceName = resourceName ?? "";
        EnvelopeName = envelopeName ?? "";
        RetryAfter = retryAfter ?? "";
        FieldViolations = fieldViolations == null ? [] : fieldViolations.ToArray();
    }

    public int StatusCode { get; }
    public int? GrpcCode { get; }
    public string TraceCode { get; }
    public string RequestId { get; }
    public string IdempotencyKey { get; }
    public string Capability { get; }
    public string ResourceName { get; }
    public string EnvelopeName { get; private set; }
    public string RetryAfter { get; }
    public IReadOnlyList<FieldViolation> FieldViolations { get; }

    public SigningflowException Attach(string? name)
    {
        EnvelopeName = name ?? "";
        return this;
    }

    public sealed class FieldViolation
    {
        public FieldViolation(string? field, string? description)
        {
            Field = field ?? "";
            Description = description ?? "";
        }

        public string Field { get; }
        public string Description { get; }
    }

    public sealed class AuthenticationException : SigningflowException
    {
        public AuthenticationException(string? message, int statusCode, int? grpcCode, string? traceCode, string? requestId, string? idempotencyKey, string? capability, string? resourceName, string? envelopeName, string? retryAfter, IReadOnlyList<FieldViolation>? fieldViolations)
            : base(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations)
        {
        }
    }

    public sealed class PermissionException : SigningflowException
    {
        public PermissionException(string? message, int statusCode, int? grpcCode, string? traceCode, string? requestId, string? idempotencyKey, string? capability, string? resourceName, string? envelopeName, string? retryAfter, IReadOnlyList<FieldViolation>? fieldViolations)
            : base(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations)
        {
        }
    }

    public sealed class IdempotencyException : SigningflowException
    {
        public IdempotencyException(string? message, int statusCode, int? grpcCode, string? traceCode, string? requestId, string? idempotencyKey, string? capability, string? resourceName, string? envelopeName, string? retryAfter, IReadOnlyList<FieldViolation>? fieldViolations)
            : base(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations)
        {
        }
    }

    public sealed class RateLimitException : SigningflowException
    {
        public RateLimitException(string? message, int statusCode, int? grpcCode, string? traceCode, string? requestId, string? idempotencyKey, string? capability, string? resourceName, string? envelopeName, string? retryAfter, IReadOnlyList<FieldViolation>? fieldViolations)
            : base(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations)
        {
        }
    }

    public sealed class InvalidRequestException : SigningflowException
    {
        public InvalidRequestException(string? message)
            : base(message)
        {
        }

        public InvalidRequestException(string? message, int statusCode, int? grpcCode, string? traceCode, string? requestId, string? idempotencyKey, string? capability, string? resourceName, string? envelopeName, string? retryAfter, IReadOnlyList<FieldViolation>? fieldViolations)
            : base(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations)
        {
        }
    }

    public sealed class ApiException : SigningflowException
    {
        public ApiException(string? message)
            : base(message)
        {
        }

        public ApiException(string? message, int statusCode)
            : base(message, statusCode, null, "", "", "", "", "", "", "", null)
        {
        }

        public ApiException(string? message, int statusCode, int? grpcCode, string? traceCode, string? requestId, string? idempotencyKey, string? capability, string? resourceName, string? envelopeName, string? retryAfter, IReadOnlyList<FieldViolation>? fieldViolations)
            : base(message, statusCode, grpcCode, traceCode, requestId, idempotencyKey, capability, resourceName, envelopeName, retryAfter, fieldViolations)
        {
        }
    }

    public sealed class ConnectionException : SigningflowException
    {
        public ConnectionException(string? message, int statusCode, string? idempotencyKey)
            : base(message, statusCode, null, "", "", idempotencyKey, "", "", "", "", null)
        {
        }
    }

    public sealed class SignatureVerificationException : SigningflowException
    {
        public SignatureVerificationException(string? message)
            : base(message)
        {
        }
    }
}
