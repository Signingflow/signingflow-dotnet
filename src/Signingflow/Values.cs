using System.Globalization;

namespace Signingflow;

internal static class Values
{
    public static string First(object? record, params string[] keys)
    {
        Dictionary<string, object?>? map = Json.AsMap(record);
        if (map == null)
        {
            return "";
        }
        foreach (string key in keys)
        {
            string value = Json.AsString(map.GetValueOrDefault(key));
            if (value.Length > 0)
            {
                return value;
            }
        }
        return "";
    }

    public static int? GrpcCode(object? body)
    {
        Dictionary<string, object?>? record = Json.AsMap(body);
        return record == null ? null : Json.AsInt(record.GetValueOrDefault("code"));
    }

    public static string ServerMessage(object? body)
    {
        if (body is string text)
        {
            return text;
        }
        Dictionary<string, object?>? record = Json.AsMap(body);
        return record == null ? "" : Json.AsString(record.GetValueOrDefault("message"));
    }

    public static string TraceCode(object? body) => FindMeta(body, "trace_code");

    public static string ResourceName(object? body)
    {
        string url = FindMeta(body, "resource_url");
        return url.Length > 0 ? url : FindMeta(body, "resource_id");
    }

    public static List<SigningflowException.FieldViolation> FieldViolations(object? body)
    {
        var found = new List<SigningflowException.FieldViolation>();
        Walk(body, record =>
        {
            object? items = record.GetValueOrDefault("fieldViolations");
            if (items is not List<object?>)
            {
                items = record.GetValueOrDefault("field_violations");
            }
            if (items is not List<object?> list)
            {
                return;
            }
            foreach (object? item in list)
            {
                Dictionary<string, object?>? row = Json.AsMap(item);
                if (row == null)
                {
                    continue;
                }
                string field = Json.AsString(row.GetValueOrDefault("field"));
                string description = Json.AsString(row.GetValueOrDefault("description"));
                if (field.Length > 0 || description.Length > 0)
                {
                    found.Add(new SigningflowException.FieldViolation(field, description));
                }
            }
        });
        return found;
    }

    public static bool MentionsIdempotency(object? body)
    {
        try
        {
            return Json.Write(body).Contains("idempotency", StringComparison.OrdinalIgnoreCase);
        }
        catch (SigningflowException)
        {
            return false;
        }
    }

    private static string FindMeta(object? body, string key)
    {
        string found = "";
        Walk(body, record =>
        {
            if (found.Length > 0)
            {
                return;
            }
            Dictionary<string, object?>? meta = Json.AsMap(record.GetValueOrDefault("metadata"));
            if (meta == null)
            {
                return;
            }
            string value = Json.AsString(meta.GetValueOrDefault(key));
            if (value.Length > 0)
            {
                found = value;
            }
        });
        return found;
    }

    private static void Walk(object? value, Action<Dictionary<string, object?>> visitor)
    {
        Dictionary<string, object?>? map = Json.AsMap(value);
        if (map != null)
        {
            visitor(map);
            foreach (object? child in map.Values)
            {
                Walk(child, visitor);
            }
            return;
        }
        if (value is List<object?> list)
        {
            foreach (object? child in list)
            {
                Walk(child, visitor);
            }
        }
    }
}
