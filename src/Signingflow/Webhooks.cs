using System.Security.Cryptography;
using System.Text;

namespace Signingflow;

public static class Webhooks
{
    public static Event ConstructEvent(byte[]? payload, string? signature, string? secret, string? previousSecret, string? previousSignature)
    {
        if (payload == null)
        {
            throw new SigningflowException.SignatureVerificationException("Pass the raw request body.");
        }
        if (string.IsNullOrEmpty(secret))
        {
            throw new SigningflowException.SignatureVerificationException("Webhook secret is required.");
        }
        string currentSignature = signature ?? "";
        string priorSecret = previousSecret ?? "";
        string priorSignature = previousSignature ?? "";
        bool current = currentSignature.Length > 0 && FixedEquals(currentSignature, Mac(secret, payload));
        bool previous = priorSecret.Length > 0 && priorSignature.Length > 0 && FixedEquals(priorSignature, Mac(priorSecret, payload));
        if (!current && !previous)
        {
            throw new SigningflowException.SignatureVerificationException("Webhook signature did not match.");
        }
        object? decoded;
        try
        {
            decoded = Json.Read(Encoding.UTF8.GetString(payload));
        }
        catch (SigningflowException.ApiException)
        {
            throw new SigningflowException.InvalidRequestException("The webhook body is not JSON.");
        }
        return new Event(decoded, Sha256(payload));
    }

    public static string BodySha256(byte[] payload) => Sha256(payload);

    private static string Mac(string secret, byte[] body)
    {
        try
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            return Convert.ToHexString(hmac.ComputeHash(body)).ToLowerInvariant();
        }
        catch (Exception)
        {
            throw new SigningflowException.SignatureVerificationException("Webhook signature did not match.");
        }
    }

    private static bool FixedEquals(string left, string right)
    {
        byte[] a = Encoding.UTF8.GetBytes(left.ToLowerInvariant());
        byte[] b = Encoding.UTF8.GetBytes(right.ToLowerInvariant());
        if (a.Length != b.Length)
        {
            CryptographicOperations.FixedTimeEquals(a, a);
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static string Sha256(byte[] payload)
    {
        try
        {
            return Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        }
        catch (Exception)
        {
            return "";
        }
    }
}
