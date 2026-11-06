using System.Globalization;

namespace Signingflow;

public sealed class Envelopes
{
    private readonly Transport _transport;
    private readonly Files _files;
    private readonly Templates _templates;

    internal Envelopes(Transport transport, Files files, Templates templates)
    {
        _transport = transport;
        _files = files;
        _templates = templates;
    }

    public async Task<Envelope> CreateAsync(string? displayName, string? description, string? storageId, string? idempotencyKey, CancellationToken cancellationToken = default)
    {
        string title = displayName?.Trim() ?? "";
        if (title.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("Name the draft title.");
        }
        string storage = storageId?.Trim() ?? "";
        if (storage.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("storage_id is required.");
        }
        var attachment = new Dictionary<string, object?> { ["storage_id"] = storage };
        var document = new Dictionary<string, object?>
        {
            ["display_name"] = title,
            ["attachments"] = new List<object?> { attachment },
            ["supplemental"] = false,
        };
        var envelope = new Dictionary<string, object?>
        {
            ["display_name"] = title,
            ["description"] = description?.Trim() ?? "",
            ["documents"] = new List<object?> { document },
        };
        Dictionary<string, object?> created = await _transport.CallAsync("EnvelopeService_AddEnvelope", new Dictionary<string, string>(), new Dictionary<string, string>(), new Dictionary<string, object?> { ["envelope"] = envelope }, idempotencyKey, cancellationToken).ConfigureAwait(false);
        return Models.Created(created);
    }

    public async Task<Envelope> RetrieveAsync(string? name, string? readMask, CancellationToken cancellationToken = default)
    {
        string envelope = Models.EnvelopeName(name);
        Dictionary<string, object?> viewed = await _transport.CallAsync(
            "EnvelopeService_ViewEnvelope",
            new Dictionary<string, string> { ["name"] = envelope },
            new Dictionary<string, string> { ["readMask"] = readMask ?? "" },
            null,
            "",
            cancellationToken).ConfigureAwait(false);
        Envelope decoded = Models.Decode(viewed);
        if (decoded.Name.Length == 0)
        {
            decoded.Name = envelope;
        }
        return decoded;
    }

    public async Task<Envelope> UpdateAsync(string? name, Dictionary<string, object?>? body, CancellationToken cancellationToken = default)
    {
        string envelope = Models.EnvelopeName(name);
        var payload = body == null ? new Dictionary<string, object?>() : new Dictionary<string, object?>(body);
        if (Json.AsString(payload.GetValueOrDefault("name")).Length == 0)
        {
            payload["name"] = envelope;
        }
        Dictionary<string, object?> updated = await _transport.CallAsync("EnvelopeService_UpdateEnvelope", new Dictionary<string, string> { ["name"] = envelope }, new Dictionary<string, string>(), payload, "", cancellationToken).ConfigureAwait(false);
        return Models.Decode(updated);
    }

    public async Task<Envelope> SendAsync(string? name, string? idempotencyKey, CancellationToken cancellationToken = default)
    {
        string envelope = Models.EnvelopeName(name);
        Dictionary<string, object?> sent = await _transport.CallAsync("EnvelopeService_SendEnvelope", new Dictionary<string, string> { ["name"] = envelope }, new Dictionary<string, string>(), new Dictionary<string, object?>(), idempotencyKey, cancellationToken).ConfigureAwait(false);
        Envelope decoded = Models.Decode(sent);
        if (decoded.Name.Length == 0)
        {
            decoded.Name = envelope;
        }
        return decoded;
    }

    public async Task<Page<Envelope>> ListAsync(string? directory, int? pageSize, string? pageToken, string? readMask, CancellationToken cancellationToken = default)
    {
        string folder = directory?.Trim() ?? "";
        if (folder.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("directory is required.");
        }
        int size = Page<Envelope>.PageSize(pageSize);
        string mask = readMask ?? "";
        Page<Envelope>.Loader load = (token, tokenCancellation) => ListPageAsync(folder, size, token, mask, tokenCancellation);
        Page<Envelope> page = await load(pageToken ?? "", cancellationToken).ConfigureAwait(false);
        return new Page<Envelope>(page.Data, page.NextPageToken, load);
    }

    public async Task<Envelope> RemindAsync(string? name, CancellationToken cancellationToken = default)
    {
        string envelope = Models.EnvelopeName(name);
        Dictionary<string, object?> reminded = await _transport.CallAsync("EnvelopeService_RemindEnvelopeSigners", new Dictionary<string, string> { ["name"] = envelope }, new Dictionary<string, string>(), new Dictionary<string, object?>(), "", cancellationToken).ConfigureAwait(false);
        Envelope decoded = Models.Decode(reminded);
        if (decoded.Name.Length == 0)
        {
            decoded.Name = envelope;
        }
        return decoded;
    }

    public async Task<Download> DownloadAsync(string? name, CancellationToken cancellationToken = default)
    {
        string envelope = Models.EnvelopeName(name);
        Dictionary<string, object?> downloaded = await _transport.CallAsync("EnvelopeService_DownloadEnvelope", new Dictionary<string, string> { ["name"] = envelope }, new Dictionary<string, string>(), null, "", cancellationToken).ConfigureAwait(false);
        return new Download(Json.AsString(downloaded.GetValueOrDefault("uri")), Values.First(downloaded, "download_time", "downloadTime"), Json.AsString(downloaded.GetValueOrDefault("etag")));
    }

    public async Task<Envelope> PrepareDraftAsync(string? title, byte[]? file, string? path, string? filename, string? message, CancellationToken cancellationToken = default)
    {
        string name = title?.Trim() ?? "";
        if (name.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("Name the PDF and the draft title.");
        }
        StoredFile stored = await _files.CreateAsync(file, path, filename, "", "", cancellationToken).ConfigureAwait(false);
        return await CreateAsync(name, message, stored.Id, "", cancellationToken).ConfigureAwait(false);
    }

    public async Task<Envelope> SendDocumentAsync(string? title, byte[]? file, string? path, string? filename, IReadOnlyList<Recipient>? recipients, string? message, CancellationToken cancellationToken = default)
    {
        string name = title?.Trim() ?? "";
        if (name.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("Name the PDF, the title, and the recipients.");
        }
        List<Recipient> people = Models.CleanRecipients(recipients);
        StoredFile stored = await _files.CreateAsync(file, path, filename, "", "", cancellationToken).ConfigureAwait(false);
        Envelope created = await CreateAsync(name, message, stored.Id, "", cancellationToken).ConfigureAwait(false);
        return await FinishSendAsync(created, people, message, name, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Envelope> SendFromTemplateAsync(string? template, IReadOnlyList<Recipient>? recipients, string? message, CancellationToken cancellationToken = default)
    {
        List<Recipient> people = Models.CleanRecipients(recipients);
        Envelope created = await _templates.UseAsync(template, "", cancellationToken).ConfigureAwait(false);
        return await FinishSendAsync(created, people, message, template ?? "", cancellationToken).ConfigureAwait(false);
    }

    public async Task<Download> DownloadCompletedAsync(string? name, CancellationToken cancellationToken = default)
    {
        string envelope = Models.EnvelopeName(name);
        Envelope viewed = await RetrieveAsync(envelope, "", cancellationToken).ConfigureAwait(false);
        if (!"COMPLETED".Equals(viewed.StateValue().Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new SigningflowException.InvalidRequestException("The signed file is not ready.").Attach(envelope);
        }
        return await DownloadAsync(envelope, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Page<Envelope>> ListPageAsync(string directory, int pageSize, string pageToken, string readMask, CancellationToken cancellationToken)
    {
        var query = new Dictionary<string, string>
        {
            ["directory"] = directory,
            ["pageSize"] = pageSize.ToString(CultureInfo.InvariantCulture),
            ["pageToken"] = pageToken,
            ["readMask"] = readMask,
        };
        Dictionary<string, object?> body = await _transport.CallAsync("EnvelopeService_ListEnvelopes", new Dictionary<string, string> { ["parent"] = "envelopes" }, query, null, "", cancellationToken).ConfigureAwait(false);
        var data = new List<Envelope>();
        foreach (object? item in Page<Envelope>.Items(body, "envelopes"))
        {
            data.Add(Models.Decode(item));
        }
        return new Page<Envelope>(data, Page<Envelope>.NextToken(body), null);
    }

    private async Task<Envelope> FinishSendAsync(Envelope created, List<Recipient> people, string? message, string label, CancellationToken cancellationToken)
    {
        string name = created.Name;
        try
        {
            Models.EnvelopeName(name);
        }
        catch (SigningflowException)
        {
            throw new SigningflowException.ApiException(label + " was saved without an envelope name.");
        }
        Envelope viewed;
        try
        {
            viewed = await RetrieveAsync(name, "documents,compliance", cancellationToken).ConfigureAwait(false);
        }
        catch (SigningflowException ex)
        {
            throw ex.Attach(name);
        }
        Dictionary<string, object?>? patched = WithRecipients(viewed, people, message);
        if (patched == null)
        {
            throw new SigningflowException.InvalidRequestException("The draft has no document to address.").Attach(name);
        }
        try
        {
            await UpdateAsync(name, patched, cancellationToken).ConfigureAwait(false);
        }
        catch (SigningflowException ex)
        {
            throw ex.Attach(name);
        }
        return await SendOrViewAsync(name, cancellationToken).ConfigureAwait(false);
    }

    private async Task<Envelope> SendOrViewAsync(string name, CancellationToken cancellationToken)
    {
        DateTimeOffset started = Clock.Instant();
        try
        {
            return await SendAsync(name, "", cancellationToken).ConfigureAwait(false);
        }
        catch (SigningflowException.IdempotencyException error)
        {
            if (name == error.ResourceName)
            {
                try
                {
                    return await RetrieveAsync(name, "", cancellationToken).ConfigureAwait(false);
                }
                catch (SigningflowException)
                {
                    throw error.Attach(name);
                }
            }
            throw error.Attach(name);
        }
        catch (SigningflowException.ConnectionException error)
        {
            try
            {
                Envelope viewed = await RetrieveAsync(name, "", cancellationToken).ConfigureAwait(false);
                DateTimeOffset? sent = Urls.ParseTime(viewed.SentTime);
                if (sent != null && SentDuring(sent.Value, started, Clock.Instant()))
                {
                    return viewed;
                }
            }
            catch (SigningflowException)
            {
                throw error.Attach(name);
            }
            throw error.Attach(name);
        }
        catch (SigningflowException error)
        {
            throw error.Attach(name);
        }
    }

    private static Dictionary<string, object?>? WithRecipients(Envelope envelope, List<Recipient> people, string? message)
    {
        var refs = new List<Dictionary<string, string>>();
        foreach (Dictionary<string, object?> item in envelope.Documents)
        {
            string uid = Values.First(item, "uid", "id");
            if (uid.Length == 0)
            {
                continue;
            }
            refs.Add(new Dictionary<string, string>
            {
                ["uid"] = uid,
                ["display_name"] = Values.First(item, "display_name", "displayName"),
            });
        }
        if (refs.Count == 0)
        {
            return null;
        }
        var participants = new List<object?>();
        for (int index = 0; index < people.Count; index++)
        {
            Recipient person = people[index];
            participants.Add(new Dictionary<string, object?>
            {
                ["uid"] = Transport.NewUuid(),
                ["display_name"] = person.Name,
                ["alternate_email"] = person.Email,
                ["role"] = "SIGNER",
                ["type"] = "PERSONAL",
                ["action_order_type"] = "SERIAL",
                ["action_order_number"] = index + 1,
            });
        }
        string profile = "STANDARD";
        if (envelope.Compliance != null && Json.AsString(envelope.Compliance.GetValueOrDefault("profile")).Length > 0)
        {
            profile = Json.AsString(envelope.Compliance.GetValueOrDefault("profile"));
        }
        string description = !string.IsNullOrWhiteSpace(message) ? message.Trim() : envelope.Description;
        var documents = new List<object?>();
        for (int i = 0; i < refs.Count; i++)
        {
            var item = new Dictionary<string, object?>
            {
                ["uid"] = refs[i]["uid"],
                ["display_name"] = refs[i]["display_name"],
            };
            if (i == 0)
            {
                item["participants"] = participants;
            }
            documents.Add(item);
        }
        return new Dictionary<string, object?>
        {
            ["name"] = envelope.Name,
            ["display_name"] = envelope.DisplayName,
            ["description"] = description,
            ["compliance"] = new Dictionary<string, object?> { ["profile"] = profile },
            ["documents"] = documents,
        };
    }

    private static bool SentDuring(DateTimeOffset sent, DateTimeOffset started, DateTimeOffset current) =>
        sent >= started && sent <= started.AddSeconds(120) && sent <= current.AddSeconds(60);
}
