using System.Globalization;

namespace Signingflow;

public sealed class WebhookUrls
{
    private readonly Transport _transport;

    internal WebhookUrls(Transport transport) => _transport = transport;

    public async Task<WebhookUrl> CreateAsync(string? displayName, string? httpRequestUri, IReadOnlyList<string>? events, object? httpConfig, string? idempotencyKey, CancellationToken cancellationToken = default)
    {
        string name = displayName?.Trim() ?? "";
        if (name.Length == 0 || name.Length > 100)
        {
            throw new SigningflowException.InvalidRequestException("display_name must be 1 to 100 characters.");
        }
        Uri uri;
        try
        {
            uri = new Uri(httpRequestUri ?? "", UriKind.Absolute);
        }
        catch (UriFormatException)
        {
            throw new SigningflowException.InvalidRequestException("http_request_uri must be an https URL.");
        }
        if (string.IsNullOrEmpty(uri.Host) || !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            throw new SigningflowException.InvalidRequestException("http_request_uri must be an https URL.");
        }
        if (events == null || events.Count == 0)
        {
            throw new SigningflowException.InvalidRequestException("events is required.");
        }
        if (httpConfig != null)
        {
            string auth;
            if (httpConfig is IDictionary<string, object?> map)
            {
                auth = map.TryGetValue("auth", out object? value) && value != null ? value.ToString() ?? "" : "";
            }
            else if (httpConfig is System.Collections.IDictionary raw)
            {
                auth = raw.Contains("auth") && raw["auth"] != null ? raw["auth"]!.ToString() ?? "" : "";
            }
            else
            {
                auth = httpConfig.ToString() ?? "";
            }
            if ("NONE".Equals(auth, StringComparison.OrdinalIgnoreCase))
            {
                throw new SigningflowException.InvalidRequestException("auth NONE has no signature. Leave http_config empty.");
            }
            throw new SigningflowException.InvalidRequestException("Leave http_config empty so the destination uses HMAC.");
        }
        var webhook = new Dictionary<string, object?>
        {
            ["displayName"] = name,
            ["httpRequestUri"] = httpRequestUri,
            ["events"] = events.ToList(),
        };
        Dictionary<string, object?> created = await _transport.CallAsync("WebhookUrlService_AddWebhookUrl", new Dictionary<string, string>(), new Dictionary<string, string>(), new Dictionary<string, object?> { ["webhookUrl"] = webhook }, idempotencyKey, cancellationToken).ConfigureAwait(false);
        return Decode(created, false);
    }

    public async Task<WebhookUrl> RetrieveAsync(string? name, CancellationToken cancellationToken = default)
    {
        string destination = Models.WebhookName(name);
        Dictionary<string, object?> viewed = await _transport.CallAsync("WebhookUrlService_ViewWebhookUrl", new Dictionary<string, string> { ["name"] = destination }, new Dictionary<string, string>(), null, "", cancellationToken).ConfigureAwait(false);
        return Decode(viewed, true);
    }

    public async Task<WebhookUrl> TestAsync(string? name, CancellationToken cancellationToken = default)
    {
        string destination = Models.WebhookName(name);
        Dictionary<string, object?> tested = await _transport.CallAsync("WebhookUrlService_TestWebhookUrl", new Dictionary<string, string> { ["name"] = destination }, new Dictionary<string, string>(), new Dictionary<string, object?>(), "", cancellationToken).ConfigureAwait(false);
        return Decode(tested, false);
    }

    public static string SigningSecretOf(object? body)
    {
        if (body is WebhookUrl url)
        {
            return url.SigningSecret;
        }
        Dictionary<string, object?>? record = Json.AsMap(body);
        if (record == null)
        {
            return "";
        }
        string secret = Json.AsString(record.GetValueOrDefault("signing_secret"));
        return secret.Length > 0 ? secret : Json.AsString(record.GetValueOrDefault("signingSecret"));
    }

    private static WebhookUrl Decode(object? body, bool dropSecret)
    {
        Dictionary<string, object?> record = Json.AsMap(body) ?? new Dictionary<string, object?>();
        record = new Dictionary<string, object?>(record);
        if (dropSecret)
        {
            record.Remove("signing_secret");
            record.Remove("signingSecret");
        }
        var events = new List<string>();
        if (record.GetValueOrDefault("events") is List<object?> raw)
        {
            foreach (object? item in raw)
            {
                string text = Json.AsString(item);
                if (text.Length > 0)
                {
                    events.Add(text);
                }
            }
        }
        return new WebhookUrl(
            Json.AsString(record.GetValueOrDefault("name")),
            Values.First(record, "displayName", "display_name"),
            Values.First(record, "httpRequestUri", "http_request_uri"),
            events,
            SigningSecretOf(record));
    }
}
