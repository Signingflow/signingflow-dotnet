using System.Reflection;
using System.Text;

namespace Signingflow;

public static class Allowlist
{
    private static IReadOnlyDictionary<string, Operation>? _byId;

    public static Operation Require(string id)
    {
        if (!Load().TryGetValue(id, out Operation? found))
        {
            throw new SigningflowException("Unknown operation.");
        }
        return found;
    }

    private static IReadOnlyDictionary<string, Operation> Load()
    {
        if (_byId != null)
        {
            return _byId;
        }
        using Stream? stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("allowlist.json");
        if (stream == null)
        {
            throw new InvalidOperationException("The allowlist could not be read.");
        }
        using var reader = new StreamReader(stream, Encoding.UTF8);
        try
        {
            object? decoded = Json.Read(reader.ReadToEnd());
            Dictionary<string, object?>? root = Json.AsMap(decoded);
            object? rawOps = root == null ? null : root.GetValueOrDefault("operations");
            if (rawOps is not List<object?> operations || operations.Count != 15)
            {
                throw new InvalidOperationException("The allowlist is invalid.");
            }
            var loaded = new Dictionary<string, Operation>(StringComparer.Ordinal);
            foreach (object? item in operations)
            {
                Dictionary<string, object?>? row = Json.AsMap(item);
                if (row == null)
                {
                    throw new InvalidOperationException("The allowlist is invalid.");
                }
                string id = Json.AsString(row.GetValueOrDefault("operationId"));
                if (id.Length == 0 || loaded.ContainsKey(id))
                {
                    throw new InvalidOperationException("The allowlist is invalid.");
                }
                loaded[id] = new Operation(
                    id,
                    Json.AsString(row.GetValueOrDefault("http")),
                    Json.AsString(row.GetValueOrDefault("path")),
                    row.GetValueOrDefault("idempotent") is true,
                    Json.AsString(row.GetValueOrDefault("capability")));
            }
            _byId = loaded;
            return _byId;
        }
        catch (SigningflowException.ApiException)
        {
            throw new InvalidOperationException("The allowlist is invalid.");
        }
    }

    public sealed record Operation(string Id, string Http, string Path, bool Idempotent, string Capability);
}
