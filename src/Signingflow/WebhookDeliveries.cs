using System.Globalization;

namespace Signingflow;

public sealed class WebhookDeliveries
{
    private readonly Transport _transport;

    internal WebhookDeliveries(Transport transport) => _transport = transport;

    public async Task<Page<WebhookDelivery>> ListAsync(int? pageSize, string? pageToken, CancellationToken cancellationToken = default)
    {
        int size = Page<WebhookDelivery>.PageSize(pageSize);
        Page<WebhookDelivery>.Loader load = (token, tokenCancellation) => ListPageAsync(size, token, tokenCancellation);
        Page<WebhookDelivery> page = await load(pageToken ?? "", cancellationToken).ConfigureAwait(false);
        return new Page<WebhookDelivery>(page.Data, page.NextPageToken, load);
    }

    public async Task<WebhookDelivery> RetrieveAsync(string? name, CancellationToken cancellationToken = default)
    {
        string delivery = Models.DeliveryName(name);
        Dictionary<string, object?> viewed = await _transport.CallAsync("WebhookService_ViewWebhook", new Dictionary<string, string> { ["name"] = delivery }, new Dictionary<string, string>(), null, "", cancellationToken).ConfigureAwait(false);
        return new WebhookDelivery(Json.AsString(viewed.GetValueOrDefault("name")), Json.AsString(viewed.GetValueOrDefault("event")));
    }

    private async Task<Page<WebhookDelivery>> ListPageAsync(int pageSize, string pageToken, CancellationToken cancellationToken)
    {
        var query = new Dictionary<string, string>
        {
            ["pageSize"] = pageSize.ToString(CultureInfo.InvariantCulture),
            ["pageToken"] = pageToken,
        };
        Dictionary<string, object?> body = await _transport.CallAsync("WebhookService_ListWebhooks", new Dictionary<string, string> { ["parent"] = "webhooks" }, query, null, "", cancellationToken).ConfigureAwait(false);
        var data = new List<WebhookDelivery>();
        foreach (object? item in Page<WebhookDelivery>.Items(body, "webhooks"))
        {
            Dictionary<string, object?>? row = Json.AsMap(item);
            if (row == null)
            {
                continue;
            }
            data.Add(new WebhookDelivery(Json.AsString(row.GetValueOrDefault("name")), Json.AsString(row.GetValueOrDefault("event"))));
        }
        return new Page<WebhookDelivery>(data, Page<WebhookDelivery>.NextToken(body), null);
    }
}
