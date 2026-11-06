using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Signingflow;

public static class Redact
{
    private static readonly Regex SecretKey = new("df_sk_[A-Za-z0-9_-]+", RegexOptions.CultureInvariant);
    private static readonly Regex Bearer = new("Bearer\\s+\\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex SignedQuery = new("([?&](?:X-Goog-Signature|Signature|sig|token)=)[^&\\s\"]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private const string Placeholder = "df_sk_redacted";

    public static string Text(string? value, string? secret)
    {
        string cleaned = value ?? "";
        if (!string.IsNullOrEmpty(secret))
        {
            cleaned = cleaned.Replace(secret, Placeholder, StringComparison.Ordinal);
        }
        cleaned = UppercasePercentHex(cleaned);
        foreach (string form in Forms(secret))
        {
            cleaned = cleaned.Replace(form, Placeholder, StringComparison.Ordinal);
        }
        cleaned = SecretKey.Replace(cleaned, Placeholder);
        cleaned = Bearer.Replace(cleaned, "Bearer [redacted]");
        return SignedQuery.Replace(cleaned, "$1[redacted]");
    }

    public static string Message(string? value, string? secret)
    {
        string cleaned = Text(value, secret);
        if (cleaned.Length <= 500)
        {
            return cleaned;
        }
        return cleaned[..500] + "…";
    }

    public static List<SigningflowException.FieldViolation> Violations(IReadOnlyList<SigningflowException.FieldViolation>? items, string? secret)
    {
        var output = new List<SigningflowException.FieldViolation>();
        if (items == null)
        {
            return output;
        }
        foreach (SigningflowException.FieldViolation item in items)
        {
            output.Add(new SigningflowException.FieldViolation(Message(item.Field, secret), Message(item.Description, secret)));
        }
        return output;
    }

    internal static string FormEncode(string value)
    {
        var output = new StringBuilder();
        foreach (byte bite in Encoding.UTF8.GetBytes(value))
        {
            int c = bite;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '*')
            {
                output.Append((char)c);
            }
            else if (c == ' ')
            {
                output.Append('+');
            }
            else
            {
                output.Append('%');
                output.Append(bite.ToString("X2", CultureInfo.InvariantCulture));
            }
        }
        return output.ToString();
    }

    private static List<string> Forms(string? secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return [];
        }
        string rfc = Urls.Rfc3986(secret);
        string form = FormEncode(secret);
        var forms = new List<string>();
        foreach (string item in new[] { secret, rfc, rfc.ToLower(CultureInfo.InvariantCulture), form, form.ToLower(CultureInfo.InvariantCulture) })
        {
            if (item.Length > 0 && !forms.Contains(item, StringComparer.Ordinal))
            {
                forms.Add(item);
            }
        }
        forms.Sort((left, right) => right.Length.CompareTo(left.Length));
        return forms;
    }

    internal static string UppercasePercentHex(string value)
    {
        var output = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char current = value[i];
            if (current == '%' && i + 2 < value.Length && Hex.FromHex(value[i + 1]) >= 0 && Hex.FromHex(value[i + 2]) >= 0)
            {
                output.Append('%');
                output.Append(char.ToUpper(value[i + 1], CultureInfo.InvariantCulture));
                output.Append(char.ToUpper(value[i + 2], CultureInfo.InvariantCulture));
                i += 2;
                continue;
            }
            output.Append(current);
        }
        return output.ToString();
    }
}
