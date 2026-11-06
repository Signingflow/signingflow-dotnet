using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Signingflow;

internal sealed class Transport : IDisposable
{
    internal const int MaxResponseBytes = 8 * 1024 * 1024;
    private static readonly System.Text.RegularExpressions.Regex UuidPattern = new("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private readonly string _apiKey;
    private readonly HttpClient _http;
    private readonly X509Certificate2? _trust;

    internal Transport(string? apiKey, ClientOptions options)
    {
        _apiKey = apiKey?.Trim() ?? "";
        if (_apiKey.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("API key is required.");
        }
        if (ClientOptions.BadHeader(_apiKey) || ClientOptions.BadHeader(options.WorkspaceId) || ClientOptions.BadHeader(options.Channel) || ClientOptions.BadHeader(options.Funnel))
        {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        Options = options;
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            ConnectTimeout = options.Timeout,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            },
        };
        if (options.CaBundle.Length > 0)
        {
            _trust = LoadTrust(options.CaBundle);
            handler.SslOptions.RemoteCertificateValidationCallback = Validate;
        }
        _http = new HttpClient(handler)
        {
            Timeout = options.Timeout,
            DefaultRequestVersion = System.Net.HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
    }

    internal string ApiKey => _apiKey;
    internal ClientOptions Options { get; }

    public void Dispose()
    {
        _http.Dispose();
        _trust?.Dispose();
    }

    internal async Task<Dictionary<string, object?>> CallAsync(string operationId, IReadOnlyDictionary<string, string>? pathParameters, IReadOnlyDictionary<string, string>? query, Dictionary<string, object?>? body, string? idempotencyKey, CancellationToken cancellationToken)
    {
        Allowlist.Operation spec = Allowlist.Require(operationId);
        string key = "";
        Dictionary<string, object?>? payload = null;
        if (spec.Http != "GET")
        {
            payload = body == null ? new Dictionary<string, object?>() : new Dictionary<string, object?>(body);
        }
        if (spec.Idempotent)
        {
            key = KeyFor(idempotencyKey, body);
            payload ??= new Dictionary<string, object?>();
            payload["idempotencyKey"] = key;
        }
        string url;
        try
        {
            string path = Urls.Fill(spec.Path, pathParameters);
            url = Urls.Resolve(Options.BaseUrl, path, query);
        }
        catch (SigningflowException.InvalidRequestException error)
        {
            throw new SigningflowException.InvalidRequestException(error.Message, error.StatusCode, error.GrpcCode, error.TraceCode, error.RequestId, key, error.Capability, error.ResourceName, error.EnvelopeName, error.RetryAfter, error.FieldViolations);
        }
        string rawQuery = "";
        int queryAt = url.IndexOf('?');
        if (queryAt >= 0)
        {
            rawQuery = url[(queryAt + 1)..];
        }
        if (Urls.ContainsSecret(rawQuery, _apiKey))
        {
            throw new SigningflowException.InvalidRequestException("The API key must not be sent in the query string.", 0, null, "", "", key, "", "", "", "", null);
        }
        int retries = spec.Http == "GET" || spec.Idempotent ? Options.MaxNetworkRetries : 0;
        byte[]? encoded = payload == null ? null : Encoding.UTF8.GetBytes(Json.Write(payload));
        int attempt = 0;
        while (true)
        {
            HttpResult result;
            try
            {
                result = await ExchangeAsync(spec.Http, url, encoded, Headers(spec.Http), cancellationToken).ConfigureAwait(false);
            }
            catch (SigningflowException)
            {
                throw;
            }
            catch (Exception error) when (error is HttpRequestException or IOException or TaskCanceledException)
            {
                if (error is OperationCanceledException && cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                if (attempt < retries)
                {
                    attempt++;
                    continue;
                }
                throw Connection(error, key);
            }
            if (result.Status >= 200 && result.Status < 300)
            {
                return ParseSuccess(result);
            }
            if (attempt < retries && Retryable(result.Status))
            {
                attempt++;
                await Clock.PauseAsync(Urls.RetryDelay(result.Header("rate-limit-retry-after"), result.Header("rate-limit-reset-after"), Clock.Instant()), cancellationToken).ConfigureAwait(false);
                continue;
            }
            throw Failure(result, spec.Capability, key);
        }
    }

    internal async Task PutBytesAsync(Uri url, string contentType, byte[]? data, CancellationToken cancellationToken)
    {
        if (ClientOptions.BadHeader(contentType))
        {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        int retries = Options.MaxNetworkRetries;
        int attempt = 0;
        var headers = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Content-Type"] = contentType,
            ["x-goog-if-generation-match"] = "0",
            ["Accept-Encoding"] = "identity",
        };
        while (true)
        {
            HttpResult result;
            try
            {
                result = await ExchangeAsync("PUT", url.OriginalString, data ?? [], headers, cancellationToken).ConfigureAwait(false);
            }
            catch (SigningflowException)
            {
                throw;
            }
            catch (Exception error) when (error is HttpRequestException or IOException or TaskCanceledException)
            {
                if (error is OperationCanceledException && cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                if (attempt < retries)
                {
                    attempt++;
                    continue;
                }
                throw new SigningflowException.ConnectionException("The upload could not be reached.", 0, "");
            }
            if ((result.Status >= 200 && result.Status < 300) || result.Status == 412)
            {
                return;
            }
            if (attempt < retries && result.Status >= 500)
            {
                attempt++;
                continue;
            }
            throw new SigningflowException.ApiException("Uploading the file to storage failed.", result.Status);
        }
    }

    private Dictionary<string, string> Headers(string method)
    {
        var header = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Authorization"] = "Bearer " + _apiKey,
            ["X-Request-Workspace-Id"] = Options.WorkspaceId,
            ["X-Request-Env"] = Options.WireEnv,
            ["X-Request-Source"] = Version.Source,
            ["Accept"] = "application/json",
            ["User-Agent"] = Version.Source,
            ["Accept-Encoding"] = "identity",
        };
        if (Options.Channel.Length > 0)
        {
            header["X-Request-Channel"] = Options.Channel;
        }
        if (Options.Funnel.Length > 0)
        {
            header["X-Request-Funnel"] = Options.Funnel;
        }
        if (method != "GET")
        {
            header["Content-Type"] = "application/json";
        }
        return header;
    }

    private async Task<HttpResult> ExchangeAsync(string method, string url, byte[]? body, Dictionary<string, string> headers, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(uri.Host))
        {
            throw new SigningflowException.InvalidRequestException("url must be https");
        }
        foreach (string value in headers.Values)
        {
            if (ClientOptions.BadHeader(value))
            {
                throw new SigningflowException.InvalidRequestException("invalid header value");
            }
        }
        using var request = new HttpRequestMessage(new HttpMethod(method), url)
        {
            Version = System.Net.HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Headers.ExpectContinue = false;
        foreach (KeyValuePair<string, string> header in headers)
        {
            if (header.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value))
            {
                throw new SigningflowException.InvalidRequestException("invalid header value");
            }
        }
        if (body != null)
        {
            var content = new ByteArrayContent(body);
            if (headers.TryGetValue("Content-Type", out string? type))
            {
                content.Headers.ContentType = new MediaTypeHeaderValue(type);
            }
            request.Content = content;
        }
        using HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        string declared = "";
        if (response.Content.Headers.ContentLength is long length)
        {
            declared = length.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        else if (response.Content.Headers.TryGetValues("Content-Length", out IEnumerable<string>? rawLengths))
        {
            declared = rawLengths.FirstOrDefault() ?? "";
        }
        byte[] captured;
        try
        {
            await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            captured = await ReadLimitedAsync(stream, declared, (int)response.StatusCode, cancellationToken).ConfigureAwait(false);
        }
        catch (SigningflowException.ApiException)
        {
            throw;
        }
        catch (IOException) when (Declared(declared) >= 0)
        {
            throw new SigningflowException.ApiException("The API response ended before the declared length.", (int)response.StatusCode);
        }
        var responseHeaders = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, IEnumerable<string>> header in response.Headers)
        {
            string? first = header.Value.FirstOrDefault();
            if (first != null)
            {
                responseHeaders[header.Key.ToLowerInvariant()] = first;
            }
        }
        foreach (KeyValuePair<string, IEnumerable<string>> header in response.Content.Headers)
        {
            string? first = header.Value.FirstOrDefault();
            if (first != null)
            {
                responseHeaders[header.Key.ToLowerInvariant()] = first;
            }
        }
        return new HttpResult((int)response.StatusCode, responseHeaders, captured);
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream stream, string declared, int status, CancellationToken cancellationToken)
    {
        long expected = -1;
        if (declared.Length > 0 && declared.All(char.IsAsciiDigit))
        {
            if (!long.TryParse(declared, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out expected))
            {
                throw new SigningflowException.ApiException("The API response is larger than 8 MB.", status);
            }
            if (expected > MaxResponseBytes)
            {
                throw new SigningflowException.ApiException("The API response is larger than 8 MB.", status);
            }
        }
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                if (output.Length + read > MaxResponseBytes)
                {
                    throw new SigningflowException.ApiException("The API response is larger than 8 MB.", status);
                }
                output.Write(buffer, 0, read);
            }
        }
        catch (SigningflowException)
        {
            throw;
        }
        catch (IOException) when (expected >= 0 && output.Length < expected)
        {
            throw new SigningflowException.ApiException("The API response ended before the declared length.", status);
        }
        if (expected >= 0 && output.Length < expected)
        {
            throw new SigningflowException.ApiException("The API response ended before the declared length.", status);
        }
        return output.ToArray();
    }

    internal static string KeyFor(string? supplied, Dictionary<string, object?>? body)
    {
        string raw = supplied?.Trim() ?? "";
        if (raw.Length == 0 && body != null && body.GetValueOrDefault("idempotencyKey") is string text)
        {
            raw = text.Trim();
        }
        if (raw.Length == 0)
        {
            return NewUuid();
        }
        if (!UuidPattern.IsMatch(raw))
        {
            throw new SigningflowException.InvalidRequestException("idempotencyKey must be a UUID.");
        }
        return raw;
    }

    internal static string NewUuid()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return Convert.ToHexString(bytes[..4]).ToLowerInvariant() + "-"
            + Convert.ToHexString(bytes.Slice(4, 2)).ToLowerInvariant() + "-"
            + Convert.ToHexString(bytes.Slice(6, 2)).ToLowerInvariant() + "-"
            + Convert.ToHexString(bytes.Slice(8, 2)).ToLowerInvariant() + "-"
            + Convert.ToHexString(bytes[10..]).ToLowerInvariant();
    }

    private SigningflowException Failure(HttpResult result, string capability, string key)
    {
        string raw = Encoding.UTF8.GetString(result.Body);
        object? parsed = raw;
        if (!string.IsNullOrWhiteSpace(raw))
        {
            try
            {
                parsed = Json.Read(raw);
            }
            catch (SigningflowException.ApiException)
            {
                parsed = raw;
            }
        }
        string message = Values.ServerMessage(parsed);
        if (message.Length == 0)
        {
            message = string.IsNullOrWhiteSpace(raw) ? "Request failed with status " + result.Status + "." : raw;
        }
        string retry = result.Header("rate-limit-retry-after");
        if (retry.Length == 0)
        {
            retry = result.Header("rate-limit-reset-after");
        }
        List<SigningflowException.FieldViolation> fields = Redact.Violations(Values.FieldViolations(parsed), _apiKey);
        message = Redact.Message(message, _apiKey);
        int status = result.Status;
        int? grpc = Values.GrpcCode(parsed);
        string trace = Values.TraceCode(parsed);
        string requestId = result.Header("x-request-id");
        if (status == 401)
        {
            return new SigningflowException.AuthenticationException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        if (status == 403)
        {
            return new SigningflowException.PermissionException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        if (status == 409 && Values.MentionsIdempotency(parsed))
        {
            return new SigningflowException.IdempotencyException(message, status, grpc, trace, requestId, key, capability, Values.ResourceName(parsed), "", retry, fields);
        }
        if (status == 429)
        {
            return new SigningflowException.RateLimitException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        if (status >= 400 && status < 500)
        {
            return new SigningflowException.InvalidRequestException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
        }
        return new SigningflowException.ApiException(message, status, grpc, trace, requestId, key, capability, "", "", retry, fields);
    }

    private static Dictionary<string, object?> ParseSuccess(HttpResult result)
    {
        string raw = Encoding.UTF8.GetString(result.Body);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new Dictionary<string, object?>();
        }
        string type = result.Header("content-type");
        if (type.Length > 0 && !type.Contains("json", StringComparison.OrdinalIgnoreCase) && !type.Contains("text/", StringComparison.OrdinalIgnoreCase))
        {
            throw new SigningflowException.ApiException("The API returned a non-JSON body.", result.Status);
        }
        if (type.Contains("gzip", StringComparison.OrdinalIgnoreCase) || result.Header("content-encoding").Contains("gzip", StringComparison.OrdinalIgnoreCase) || Gzip(result.Body))
        {
            throw new SigningflowException.ApiException("The API returned invalid JSON.", result.Status);
        }
        object? decoded;
        try
        {
            decoded = Json.Read(raw);
        }
        catch (SigningflowException.ApiException)
        {
            throw new SigningflowException.ApiException("The API returned invalid JSON.", result.Status);
        }
        if (decoded is not Dictionary<string, object?> map)
        {
            throw new SigningflowException.ApiException("The API returned invalid JSON.", result.Status);
        }
        return map;
    }

    private static bool Gzip(byte[] body) => body.Length >= 2 && body[0] == 0x1f && body[1] == 0x8b;

    private static bool Retryable(int status) => status == 408 || status == 429 || status >= 500;

    private static SigningflowException.ConnectionException Connection(Exception error, string key)
    {
        string text = error.Message.ToLowerInvariant();
        if (text.Contains("timed out") || text.Contains("timeout"))
        {
            return new SigningflowException.ConnectionException("The API timed out.", 408, key);
        }
        return new SigningflowException.ConnectionException("The API could not be reached.", 0, key);
    }

    private static bool HostnameMatches(object sender, X509Certificate2 presented, SslPolicyErrors errors)
    {
        if (!errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return true;
        }
        if (sender is SslStream stream && !string.IsNullOrEmpty(stream.TargetHostName))
        {
            return presented.MatchesHostname(stream.TargetHostName);
        }
        return false;
    }

    private bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (_trust == null || certificate == null)
        {
            return false;
        }
        using var presented = new X509Certificate2(certificate);
        if (!HostnameMatches(sender, presented, errors))
        {
            return false;
        }
        if (string.Equals(presented.Thumbprint, _trust.Thumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        using var custom = new X509Chain();
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.Add(_trust);
        return custom.Build(presented);
    }

    private static X509Certificate2 LoadTrust(string pemPath)
    {
        try
        {
            string text = File.ReadAllText(pemPath);
            return X509Certificate2.CreateFromPem(text);
        }
        catch (Exception)
        {
            throw new SigningflowException.InvalidRequestException("ca_bundle could not be read.");
        }
    }

    private static long Declared(string declared) =>
        declared.Length > 0 && declared.All(char.IsAsciiDigit) && long.TryParse(declared, out long value) ? value : -1;

    private sealed record HttpResult(int Status, Dictionary<string, string> Headers, byte[] Body)
    {
        public string Header(string name) => Headers.TryGetValue(name, out string? value) ? value : "";
    }
}
