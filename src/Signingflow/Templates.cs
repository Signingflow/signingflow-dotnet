namespace Signingflow;

public sealed class Templates
{
    private readonly Transport _transport;

    internal Templates(Transport transport) => _transport = transport;

    public async Task<Envelope> UseAsync(string? template, string? idempotencyKey, CancellationToken cancellationToken = default)
    {
        string name = Models.TemplateName(template);
        Dictionary<string, object?> created = await _transport.CallAsync(
            "TemplateService_UseTemplate",
            new Dictionary<string, string> { ["name"] = name },
            new Dictionary<string, string>(),
            new Dictionary<string, object?>(),
            idempotencyKey,
            cancellationToken).ConfigureAwait(false);
        return Models.Created(created);
    }
}
