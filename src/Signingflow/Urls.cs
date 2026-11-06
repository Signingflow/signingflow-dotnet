using System.Globalization;
using System.Text;

namespace Signingflow;

public static class Urls
{
    public const string OfficialHost = "api.signingflow.com";
    private static readonly System.Text.RegularExpressions.Regex Segment = new("^[A-Za-z0-9_-]+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    public static string Rfc3986(string value)
    {
        var output = new StringBuilder();
        foreach (byte bite in Encoding.UTF8.GetBytes(value))
        {
            int c = bite;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
            {
                output.Append((char)c);
            }
            else
            {
                output.Append('%');
                output.Append(bite.ToString("X2", CultureInfo.InvariantCulture));
            }
        }
        return output.ToString();
    }

    public static string Fill(string template, IReadOnlyDictionary<string, string>? parameters)
    {
        var output = new StringBuilder();
        int index = 0;
        while (index < template.Length)
        {
            int start = template.IndexOf('{', index);
            if (start < 0)
            {
                output.Append(template[index..]);
                break;
            }
            output.Append(template, index, start - index);
            int end = template.IndexOf('}', start);
            if (end < 0)
            {
                throw new SigningflowException.InvalidRequestException("invalid path");
            }
            string token = template[(start + 1)..end];
            int equals = token.IndexOf('=');
            string name = equals < 0 ? token : token[..equals];
            int dot = name.LastIndexOf('.');
            string shortName = dot < 0 ? name : name[(dot + 1)..];
            string value = "";
            if (parameters != null)
            {
                if (!parameters.TryGetValue(name, out value!))
                {
                    parameters.TryGetValue(shortName, out value!);
                }
                value ??= "";
            }
            if (value.Length == 0 && (shortName == "name" || shortName.StartsWith("name_", StringComparison.Ordinal)))
            {
                if (parameters != null && parameters.TryGetValue("name", out string? fallback))
                {
                    value = fallback;
                }
            }
            if (value.Length == 0)
            {
                throw new SigningflowException.InvalidRequestException("missing path param " + shortName);
            }
            string[] parts = value.Split('/');
            for (int i = 0; i < parts.Length; i++)
            {
                if (!Segment.IsMatch(parts[i]))
                {
                    throw new SigningflowException.InvalidRequestException("invalid path param " + shortName);
                }
                if (i > 0)
                {
                    output.Append('/');
                }
                output.Append(Rfc3986(parts[i]));
            }
            index = end + 1;
        }
        return output.ToString();
    }

    public static string Resolve(string baseUrl, string path, IReadOnlyDictionary<string, string>? query)
    {
        Uri baseUri = Parse(baseUrl);
        if (!path.StartsWith('/'))
        {
            throw new SigningflowException.InvalidRequestException("invalid path");
        }
        string origin = Origin(baseUri);
        Uri built = Parse(origin + path);
        if (!SameOrigin(baseUri, built))
        {
            throw new SigningflowException.InvalidRequestException("invalid path");
        }
        string rawQuery = Encode(query);
        string rawPath = string.IsNullOrEmpty(built.AbsolutePath) ? "/" : built.AbsolutePath;
        string url = origin + rawPath;
        if (rawQuery.Length > 0)
        {
            url += "?" + rawQuery;
        }
        return url;
    }

    public static string Encode(IReadOnlyDictionary<string, string>? query)
    {
        if (query == null || query.Count == 0)
        {
            return "";
        }
        var pairs = new List<string>();
        foreach (KeyValuePair<string, string> entry in query)
        {
            if (string.IsNullOrEmpty(entry.Value))
            {
                continue;
            }
            pairs.Add(Rfc3986(entry.Key) + "=" + Rfc3986(entry.Value));
        }
        return string.Join("&", pairs);
    }

    public static bool ContainsSecret(string? rawQuery, string? secret)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(rawQuery))
        {
            return false;
        }
        if (rawQuery.Contains(secret, StringComparison.Ordinal) || rawQuery.Contains(Rfc3986(secret), StringComparison.Ordinal) || rawQuery.Contains(Redact.FormEncode(secret), StringComparison.Ordinal))
        {
            return true;
        }
        if (BadPercent(rawQuery))
        {
            return true;
        }
        foreach (string part in rawQuery.Split('&'))
        {
            int eq = part.IndexOf('=');
            string value = eq < 0 ? part : part[(eq + 1)..];
            if (Decoded(value, false).Contains(secret, StringComparison.Ordinal) || Decoded(value, true).Contains(secret, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    public static Uri AllowedUploadUrl(string? raw, IReadOnlyList<string> hosts)
    {
        if (raw == null || raw.Contains('\0'))
        {
            throw new SigningflowException.InvalidRequestException("upload url rejected");
        }
        Uri uri = Parse(raw);
        if (uri.Scheme != "https")
        {
            throw new SigningflowException.InvalidRequestException("upload url must be https");
        }
        if (!string.IsNullOrEmpty(uri.UserInfo) || AuthorityFrom(uri.OriginalString).Contains('@'))
        {
            throw new SigningflowException.InvalidRequestException("upload url rejected");
        }
        string host = HostOf(uri);
        if (host.EndsWith('.'))
        {
            throw new SigningflowException.InvalidRequestException("upload url rejected");
        }
        string lower = host.ToLower(CultureInfo.InvariantCulture);
        foreach (string item in hosts)
        {
            if (lower.Equals(item, StringComparison.Ordinal) || lower.EndsWith("." + item, StringComparison.Ordinal))
            {
                return uri;
            }
        }
        throw new SigningflowException.InvalidRequestException("upload host rejected");
    }

    public static TimeSpan RetryDelay(string? retryAfter, string? resetAfter, DateTimeOffset now)
    {
        DateTimeOffset? when = ParseTime(retryAfter) ?? ParseTime(resetAfter);
        if (when == null)
        {
            return TimeSpan.Zero;
        }
        long seconds = when.Value.ToUnixTimeSeconds() - now.ToUnixTimeSeconds();
        if (seconds < 0)
        {
            return TimeSpan.Zero;
        }
        if (seconds > 60)
        {
            return TimeSpan.FromSeconds(60);
        }
        return TimeSpan.FromSeconds(seconds);
    }

    public static DateTimeOffset? ParseTime(string? value)
    {
        if (value == null)
        {
            return null;
        }
        string text = value.Trim();
        if (text.Length == 0)
        {
            return null;
        }
        if (text.EndsWith('Z'))
        {
            text = text[..^1] + "+00:00";
        }
        try
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(text, @"(?:Z|[+-]\d{2}:?\d{2})$"))
            {
                return DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            }
            return DateTimeOffset.Parse(text + "+00:00", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    public static string HostOf(Uri uri)
    {
        string raw = RawAuthority(uri);
        if (raw.Contains('@'))
        {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        if (raw.StartsWith('['))
        {
            int end = raw.IndexOf(']');
            if (end < 0)
            {
                throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
            }
            return raw[..(end + 1)];
        }
        int colon = raw.LastIndexOf(':');
        if (colon > 0 && raw.IndexOf(':') == colon)
        {
            return raw[..colon];
        }
        return raw;
    }

    public static Uri Parse(string? raw)
    {
        if (raw == null || raw.Contains('\0'))
        {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        if (!Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri) || string.IsNullOrEmpty(uri.Scheme) || string.IsNullOrEmpty(RawAuthority(uri)))
        {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        return uri;
    }

    private static string Origin(Uri uri) => uri.Scheme + "://" + RawAuthority(uri);

    private static string AuthorityFrom(string raw)
    {
        int scheme = raw.IndexOf("://", StringComparison.Ordinal);
        if (scheme < 0)
        {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        int start = scheme + 3;
        int end = start;
        while (end < raw.Length && raw[end] != '/' && raw[end] != '?' && raw[end] != '#')
        {
            end++;
        }
        string authority = raw[start..end];
        if (authority.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("base_url must be an absolute URL.");
        }
        return authority;
    }

    private static bool SameOrigin(Uri left, Uri right) =>
        left.Scheme == right.Scheme && HostOf(left) == HostOf(right) && left.Port == right.Port;

    private static string RawAuthority(Uri uri) => AuthorityFrom(uri.OriginalString);

    private static string Decoded(string value, bool plus)
    {
        string text = plus ? value.Replace("+", " ", StringComparison.Ordinal) : value;
        try
        {
            return Uri.UnescapeDataString(text);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }

    private static bool BadPercent(string raw)
    {
        for (int i = 0; i < raw.Length; i++)
        {
            if (raw[i] != '%')
            {
                continue;
            }
            if (i + 2 >= raw.Length)
            {
                return true;
            }
            if (Hex.FromHex(raw[i + 1]) < 0 || Hex.FromHex(raw[i + 2]) < 0)
            {
                return true;
            }
            i += 2;
        }
        return false;
    }
}
