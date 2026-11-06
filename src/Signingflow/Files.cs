using System.Globalization;

namespace Signingflow;

public sealed class Files
{
    private const int MaxBytes = 25 * 1024 * 1024;
    private static readonly Dictionary<string, string> Mime = new(StringComparer.Ordinal)
    {
        ["pdf"] = "application/pdf",
        ["png"] = "image/png",
        ["jpg"] = "image/jpeg",
        ["jpeg"] = "image/jpeg",
        ["txt"] = "text/plain",
        ["json"] = "application/json",
    };

    private readonly Transport _transport;

    internal Files(Transport transport) => _transport = transport;

    public async Task<StoredFile> CreateAsync(byte[]? file, string? path, string? filename, string? mimeType, string? idempotencyKey, CancellationToken cancellationToken = default)
    {
        Loaded loaded = Load(file, path, filename, mimeType);
        var storage = new Dictionary<string, object?>
        {
            ["originalName"] = loaded.Filename,
            ["displayName"] = loaded.Filename,
            ["size"] = loaded.Data.Length.ToString(CultureInfo.InvariantCulture),
            ["extension"] = loaded.Extension,
            ["mimeType"] = loaded.Mime,
        };
        Dictionary<string, object?> added = await _transport.CallAsync(
            "StorageService_BatchAddStorage",
            new Dictionary<string, string>(),
            new Dictionary<string, string>(),
            new Dictionary<string, object?> { ["storages"] = new List<object?> { storage } },
            idempotencyKey,
            cancellationToken).ConfigureAwait(false);
        string[]? found = Models.FindStorage(added);
        if (found == null)
        {
            throw new SigningflowException.ApiException("Storage did not return an upload URL.");
        }
        Uri upload = Urls.AllowedUploadUrl(found[2], _transport.Options.UploadHosts);
        await _transport.PutBytesAsync(upload, loaded.Mime, loaded.Data, cancellationToken).ConfigureAwait(false);
        await _transport.CallAsync(
            "StorageService_BatchAcknowledgeUpload",
            new Dictionary<string, string>(),
            new Dictionary<string, string>(),
            new Dictionary<string, object?> { ["names"] = new List<object?> { found[0] } },
            "",
            cancellationToken).ConfigureAwait(false);
        return new StoredFile(found[0], found[1]);
    }

    private Loaded Load(byte[]? file, string? path, string? filename, string? mimeType)
    {
        bool hasFile = file != null;
        string requested = path?.Trim() ?? "";
        bool hasPath = requested.Length > 0;
        if (hasFile && hasPath)
        {
            throw new SigningflowException.InvalidRequestException("Pass file bytes or a path, not both.");
        }
        if (!hasFile && !hasPath)
        {
            throw new SigningflowException.InvalidRequestException("Pass file bytes or a path.");
        }
        byte[] data = hasFile ? file! : Jail.Read(_transport.Options.UploadRoot, requested);
        if (data.Length > MaxBytes)
        {
            throw new SigningflowException.InvalidRequestException("The file is larger than 25 MB.");
        }
        string name = filename?.Trim() ?? "";
        if (name.Length == 0 && hasPath)
        {
            int slash = Math.Max(requested.LastIndexOf('/'), requested.LastIndexOf('\\'));
            name = slash < 0 ? requested : requested[(slash + 1)..];
        }
        if (name.Length == 0 || name == "." || name == "/")
        {
            throw new SigningflowException.InvalidRequestException("filename is required when file is not a path.");
        }
        int dot = name.LastIndexOf('.');
        string extension = dot < 0 ? "" : name[(dot + 1)..].ToLower(CultureInfo.InvariantCulture);
        string mime = mimeType?.Trim() ?? "";
        if (mime.Length == 0)
        {
            mime = Mime.TryGetValue(extension, out string? known) ? known : "";
        }
        if (mime.Length == 0)
        {
            mime = "application/octet-stream";
        }
        if (ClientOptions.BadHeader(mime))
        {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        return new Loaded(data, name, extension, mime);
    }

    private sealed record Loaded(byte[] Data, string Filename, string Extension, string Mime);
}
