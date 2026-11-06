namespace Signingflow;

public sealed class SigningflowClient : IDisposable
{
    private readonly Transport _transport;

    public SigningflowClient(string? apiKey, ClientOptions? options)
    {
        if (options == null)
        {
            throw new SigningflowException.InvalidRequestException("workspace_id is required.");
        }
        Options = options;
        _transport = new Transport(apiKey, options);
        Files = new Files(_transport);
        Templates = new Templates(_transport);
        Envelopes = new Envelopes(_transport, Files, Templates);
        WebhookUrls = new WebhookUrls(_transport);
        WebhookDeliveries = new WebhookDeliveries(_transport);
    }

    public ClientOptions Options { get; }
    public Files Files { get; }
    public Templates Templates { get; }
    public Envelopes Envelopes { get; }
    public WebhookUrls WebhookUrls { get; }
    public WebhookDeliveries WebhookDeliveries { get; }

    public void Dispose() => _transport.Dispose();
}
