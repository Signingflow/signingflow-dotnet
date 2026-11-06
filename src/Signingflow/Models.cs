using System.Globalization;
using System.Text.RegularExpressions;

namespace Signingflow;

public sealed class Envelope
{
    internal Envelope(string name, string uid, string displayName, string description, string progressStatus, string state, string condition, string sentTime, List<Dictionary<string, object?>> documents, Dictionary<string, object?>? compliance, Dictionary<string, object?>? progress)
    {
        Name = name;
        Uid = uid;
        DisplayName = displayName;
        Description = description;
        ProgressStatus = progressStatus;
        State = state;
        Condition = condition;
        SentTime = sentTime;
        Documents = documents;
        Compliance = compliance;
        Progress = progress;
    }

    public string Name { get; internal set; }
    public string Uid { get; }
    public string DisplayName { get; }
    public string Description { get; }
    public string SentTime { get; }
    public IReadOnlyList<Dictionary<string, object?>> Documents { get; }
    public Dictionary<string, object?>? Compliance { get; }
    internal string ProgressStatus { get; }
    internal string State { get; }
    internal string Condition { get; }
    internal Dictionary<string, object?>? Progress { get; }

    internal string StateValue()
    {
        if (Progress != null)
        {
            string nested = Json.AsString(Progress.GetValueOrDefault("state"));
            if (nested.Length > 0)
            {
                return nested;
            }
        }
        if (ProgressStatus.Length > 0)
        {
            return ProgressStatus;
        }
        if (State.Length > 0)
        {
            return State;
        }
        return Condition;
    }
}

public sealed class Recipient
{
    public Recipient(string? name, string? email)
    {
        Name = name;
        Email = email;
    }

    public string? Name { get; }
    public string? Email { get; }
}

public sealed class StoredFile
{
    internal StoredFile(string name, string id)
    {
        Name = name;
        Id = id;
    }

    public string Name { get; }
    public string Id { get; }
}

public sealed class Download
{
    internal Download(string uri, string downloadTime, string etag)
    {
        Uri = uri;
        DownloadTime = downloadTime;
        Etag = etag;
    }

    public string Uri { get; }
    public string DownloadTime { get; }
    public string Etag { get; }
}

public sealed class WebhookUrl
{
    internal WebhookUrl(string name, string displayName, string httpRequestUri, List<string> events, string signingSecret)
    {
        Name = name;
        DisplayName = displayName;
        HttpRequestUri = httpRequestUri;
        Events = events;
        SigningSecret = signingSecret;
    }

    public string Name { get; }
    public string DisplayName { get; }
    public string HttpRequestUri { get; }
    public IReadOnlyList<string> Events { get; }
    public string SigningSecret { get; }
}

public sealed class WebhookDelivery
{
    internal WebhookDelivery(string name, string eventName)
    {
        Name = name;
        Event = eventName;
    }

    public string Name { get; }
    public string Event { get; }
}

public sealed class Event
{
    internal Event(object? payload, string bodySha256)
    {
        Payload = payload;
        BodySha256 = bodySha256;
    }

    public object? Payload { get; }
    public string BodySha256 { get; }
}

public static class Models
{
    private static readonly Regex EnvelopeNamePattern = new("^envelopes/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex TemplateNamePattern = new("^templates/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex WebhookNamePattern = new("^webhookUrls/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex DeliveryNamePattern = new("^webhooks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex StoragePattern = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex EmailPattern = new("^[^\\s@]+@[^\\s@]+$", RegexOptions.CultureInvariant);

    public static string EnvelopeName(string? name)
    {
        string value = name?.Trim() ?? "";
        if (!EnvelopeNamePattern.IsMatch(value))
        {
            throw new SigningflowException.InvalidRequestException("envelope must look like envelopes/{id}.");
        }
        return value;
    }

    public static string TemplateName(string? name)
    {
        string value = name?.Trim() ?? "";
        if (!TemplateNamePattern.IsMatch(value))
        {
            throw new SigningflowException.InvalidRequestException("template must look like templates/{id}.");
        }
        return value;
    }

    public static string WebhookName(string? name)
    {
        string value = name?.Trim() ?? "";
        if (!WebhookNamePattern.IsMatch(value))
        {
            throw new SigningflowException.InvalidRequestException("webhook url must look like webhookUrls/{id}.");
        }
        return value;
    }

    public static string DeliveryName(string? name)
    {
        string value = name?.Trim() ?? "";
        if (!DeliveryNamePattern.IsMatch(value))
        {
            throw new SigningflowException.InvalidRequestException("webhook delivery must look like webhooks/{id}.");
        }
        return value;
    }

    public static List<Recipient> CleanRecipients(IReadOnlyList<Recipient>? recipients)
    {
        if (recipients == null || recipients.Count == 0)
        {
            throw new SigningflowException.InvalidRequestException("Each recipient needs a name and an email.");
        }
        var people = new List<Recipient>();
        foreach (Recipient? person in recipients)
        {
            string personName = person?.Name?.Trim() ?? "";
            string email = person?.Email?.Trim() ?? "";
            if (personName.Length == 0 || !EmailPattern.IsMatch(email))
            {
                throw new SigningflowException.InvalidRequestException("Each recipient needs a name and an email.");
            }
            people.Add(new Recipient(personName, email));
        }
        return people;
    }

    public static Envelope Decode(object? body)
    {
        Dictionary<string, object?> record = Json.AsMap(body) ?? new Dictionary<string, object?>();
        Dictionary<string, object?>? nested = Json.AsMap(record.GetValueOrDefault("envelope"));
        if (nested != null)
        {
            record = nested;
        }
        var documents = new List<Dictionary<string, object?>>();
        if (record.GetValueOrDefault("documents") is List<object?> raw)
        {
            foreach (object? item in raw)
            {
                Dictionary<string, object?>? doc = Json.AsMap(item);
                if (doc != null)
                {
                    documents.Add(doc);
                }
            }
        }
        return new Envelope(
            Json.AsString(record.GetValueOrDefault("name")),
            Json.AsString(record.GetValueOrDefault("uid")),
            Values.First(record, "display_name", "displayName"),
            Json.AsString(record.GetValueOrDefault("description")),
            Values.First(record, "progress_status", "progressStatus"),
            Json.AsString(record.GetValueOrDefault("state")),
            Json.AsString(record.GetValueOrDefault("condition")),
            Values.First(record, "sent_time", "sentTime"),
            documents,
            Json.AsMap(record.GetValueOrDefault("compliance")),
            Json.AsMap(record.GetValueOrDefault("progress")));
    }

    public static string NameOf(object? body)
    {
        Dictionary<string, object?> record = Json.AsMap(body) ?? new Dictionary<string, object?>();
        Dictionary<string, object?> nested = Json.AsMap(record.GetValueOrDefault("envelope")) ?? new Dictionary<string, object?>();
        string name = Json.AsString(nested.GetValueOrDefault("name"));
        if (name.Length == 0)
        {
            name = Json.AsString(record.GetValueOrDefault("name"));
        }
        if (name.StartsWith("envelopes/", StringComparison.Ordinal))
        {
            return name;
        }
        string uid = Json.AsString(nested.GetValueOrDefault("uid"));
        if (uid.Length == 0)
        {
            uid = Json.AsString(record.GetValueOrDefault("uid"));
        }
        return uid.Length == 0 ? "" : "envelopes/" + uid;
    }

    public static Envelope Created(object? body)
    {
        Envelope envelope = Decode(body);
        string name = NameOf(body);
        if (name.Length > 0)
        {
            envelope.Name = name;
        }
        else if (envelope.Name.Length == 0 && envelope.Uid.Length > 0)
        {
            envelope.Name = "envelopes/" + envelope.Uid;
        }
        return envelope;
    }

    public static string[]? FindStorage(object? body)
    {
        Dictionary<string, object?>? record = Json.AsMap(body);
        if (record != null && record.ContainsKey("storages"))
        {
            string[]? found = FindStorage(record["storages"]);
            if (found != null)
            {
                return found;
            }
        }
        return WalkStorage(body);
    }

    private static string[]? WalkStorage(object? body)
    {
        Dictionary<string, object?>? map = Json.AsMap(body);
        if (map != null)
        {
            string rawUrl = Values.First(map, "pre_signed_url", "preSignedUrl");
            string name = Json.AsString(map.GetValueOrDefault("name"));
            string fileId = name.Contains('/') ? name[(name.LastIndexOf('/') + 1)..] : name;
            if (name.StartsWith("storages/", StringComparison.Ordinal) && StoragePattern.IsMatch(fileId) && rawUrl.Length > 0)
            {
                return [name, fileId, rawUrl];
            }
            foreach (KeyValuePair<string, object?> entry in map)
            {
                if (entry.Key == "storages")
                {
                    continue;
                }
                string[]? found = WalkStorage(entry.Value);
                if (found != null)
                {
                    return found;
                }
            }
            return null;
        }
        if (body is List<object?> list)
        {
            foreach (object? child in list)
            {
                string[]? found = WalkStorage(child);
                if (found != null)
                {
                    return found;
                }
            }
        }
        return null;
    }
}
