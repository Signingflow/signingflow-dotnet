using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Signingflow.Tests;

[Collection("tls")]
public sealed class SdkTests : IDisposable
{
    private const string EnvelopeName = "envelopes/11111111-1111-4111-8111-111111111111";
    private const string TemplateName = "templates/11111111-1111-4111-8111-111111111111";
    private const string WebhookName = "webhookUrls/11111111-1111-4111-8111-111111111111";
    private const string DeliveryName = "webhooks/11111111-1111-4111-8111-111111111111";
    private const string StorageName = "storages/22222222-2222-4222-8222-222222222222";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-06T00:00:00Z");

    private readonly LocalTls _server;
    private readonly List<SigningflowClient> _clients = [];

    public SdkTests(TlsFixture fixture)
    {
        _server = fixture.Server;
        _server.Reset();
        Clock.Now = () => Now;
        Clock.Delay = (_, _) => Task.CompletedTask;
    }

    public void Dispose()
    {
        foreach (SigningflowClient client in _clients)
        {
            client.Dispose();
        }
        Clock.Reset();
    }

    [Fact]
    public void ConfigRejectsUnsafeValues()
    {
        Assert.Equal("workspace_id is required.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["workspace"] = "" })).Message);
        Assert.Equal("API key is required.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["key"] = "  " })).Message);
        Assert.Equal("env must be sandbox or live.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["env"] = "prod" })).Message);
        Assert.Equal("base_url must be https.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["base"] = "http://api.signingflow.com" })).Message);
        Assert.Equal("base_url must not include a username or password.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["base"] = "https://user:pass@api.signingflow.com" })).Message);
        Assert.Contains("api.signingflow.com", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["base"] = "https://API.SIGNINGFLOW.COM" })).Message);
        Assert.Equal("timeout must be positive.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["timeout"] = "0" })).Message);
        Assert.Equal("max_network_retries must be a whole number of zero or more.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["retries"] = "-1" })).Message);
        Assert.Equal("invalid header value", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["key"] = "df_sk_a\nb" })).Message);
        Assert.Equal("invalid header value", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["channel"] = "a\rb" })).Message);
        Assert.Contains("upload_hosts", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["hosts"] = new List<string> { "evil.com" } })).Message);
        Assert.Contains("upload_hosts", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["hosts"] = new List<string> { ".example.com" } })).Message);
        Assert.Equal("ca_bundle could not be read.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["ca"] = Path.Combine(Path.GetDirectoryName(_server.Certificate)!, "missing.pem") })).Message);
        Assert.Equal("workspace_id is required.", Assert.Throws<SigningflowException.InvalidRequestException>(() => new SigningflowClient("df_sk_test", null)).Message);
        SigningflowClient live = Client(new Dictionary<string, object?> { ["env"] = "LIVE", ["base"] = "https://api.signingflow.com:444/", ["channel"] = " desk ", ["funnel"] = " mail " });
        Assert.Equal("LIVE", live.Options.WireEnv);
        Assert.Equal("https://api.signingflow.com:444", live.Options.BaseUrl);
        Assert.Equal("desk", live.Options.Channel);
        Assert.Equal("mail", live.Options.Funnel);
    }

    [Fact]
    public async Task SendDocumentAndUploadContract()
    {
        string upload = "https://127.0.0.1:" + _server.Port + "/bucket/a";
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(412, "");
        _server.Json("{}");
        _server.Json("{\"envelope\":{\"name\":\"" + EnvelopeName + "\",\"display_name\":\"Contract\"}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"display_name\":\"Contract\",\"documents\":[{\"uid\":\"doc-1\",\"display_name\":\"Contract\"}],\"compliance\":{\"profile\":\"QES\"}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"sent_time\":\"2026-11-06T00:00:00Z\"}");
        Envelope sent = await Client().Envelopes.SendDocumentAsync("Contract", Encoding.UTF8.GetBytes("%PDF"), null, "contract.pdf", [new Recipient("Ada", "ada@example.com")], "Please sign");
        Assert.Equal(EnvelopeName, sent.Name);
        LocalTls.Hit? put = null;
        foreach (LocalTls.Hit hit in Hits())
        {
            Assert.Equal("identity", hit.Header("accept-encoding"));
            Assert.False(hit.Headers.ContainsKey("x-api-key"));
            if (hit.Method == "PUT")
            {
                put = hit;
            }
        }
        Assert.NotNull(put);
        Assert.Equal("application/pdf", put.Header("content-type"));
        Assert.Equal("0", put.Header("x-goog-if-generation-match"));
        Assert.Equal("", put.Header("authorization"));
        LocalTls.Hit add = Hits()[0];
        Assert.Equal("Bearer df_sk_test", add.Header("authorization"));
        Assert.Equal("ws", add.Header("x-request-workspace-id"));
        Assert.Equal("SANDBOX", add.Header("x-request-env"));
        Assert.Equal("signingflow-dotnet/0.1.0", add.Header("x-request-source"));
        Assert.Contains("idempotencyKey", add.Text());
        Assert.Contains("application/pdf", add.Text());
        Assert.DoesNotContain(Hits(), hit => hit.Path.Contains("/secret"));
    }

    [Fact]
    public async Task RefusesEncodedApiKeyBeforeCalling()
    {
        string secret = "df_sk_a/b c+";
        _server.Json("{\"envelopes\":[]}");
        SigningflowException.InvalidRequestException error = await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["key"] = secret }).Envelopes.ListAsync(secret, null, null, null));
        Assert.Equal("The API key must not be sent in the query string.", error.Message);
        Assert.Empty(Hits());
        Assert.True(Urls.ContainsSecret("directory=" + Urls.Rfc3986(secret), secret));
        Assert.True(Urls.ContainsSecret("pageToken=%zz", secret));
        Assert.False(Urls.ContainsSecret("", secret));
    }

    [Fact]
    public async Task RedactsSlashKeyFromAnApiError()
    {
        string secret = "df_sk_a/b c+";
        string lowerRfc = Urls.Rfc3986(secret).ToLowerInvariant();
        string lowerForm = Redact.FormEncode(secret).ToLowerInvariant();
        string mixed = "df_sk_a%2fb%20c%2B";
        string echoed = secret + " " + Urls.Rfc3986(secret) + " " + Redact.FormEncode(secret) + " " + lowerRfc + " " + lowerForm + " " + mixed;
        _server.Json(400, "{\"message\":\"" + JsonEscape(echoed) + "\",\"details\":[{\"fieldViolations\":[{\"field\":\"" + JsonEscape(lowerRfc) + "\",\"description\":\"Bearer " + JsonEscape(secret) + "\"}]}]}");
        SigningflowException.InvalidRequestException error = await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client(new Dictionary<string, object?> { ["key"] = secret }).Envelopes.RetrieveAsync(EnvelopeName, ""));
        string text = error.Message + error.FieldViolations[0].Field + error.FieldViolations[0].Description;
        Assert.DoesNotContain(secret, text);
        Assert.DoesNotContain("/b c+", text);
        Assert.DoesNotContain("c+", text);
        Assert.DoesNotContain("%2f", text.ToLowerInvariant());
        Assert.DoesNotContain("%2b", text.ToLowerInvariant());
        Assert.DoesNotContain("%20", text);
        Assert.True(error.Message.Length <= 501);
    }

    [Fact]
    public async Task RetriesIdempotentCallsAndNotUpdates()
    {
        _server.Mode("stall", 200, "{}");
        SigningflowException.ConnectionException timed = await Assert.ThrowsAsync<SigningflowException.ConnectionException>(() => Client(new Dictionary<string, object?> { ["timeout"] = "300", ["retries"] = "0" }).Envelopes.UpdateAsync(EnvelopeName, new Dictionary<string, object?> { ["display_name"] = "Later" }));
        Assert.Equal(408, timed.StatusCode);
        Assert.Single(Hits());

        _server.Reset();
        _server.Json(500, "{\"message\":\"later\"}");
        _server.Json(500, "{\"message\":\"later\"}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        Envelope viewed = await Client().Envelopes.RetrieveAsync(EnvelopeName, "");
        Assert.Equal(EnvelopeName, viewed.Name);
        Assert.Equal(3, Hits().Count);

        _server.Reset();
        _server.Json(500, "{\"message\":\"no\"}");
        await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client().Envelopes.RemindAsync(EnvelopeName));
        Assert.Single(Hits());
    }

    [Fact]
    public async Task ResponseLimitsAndRedirects()
    {
        _server.Mode("huge", 200, "{\"name\":\"" + EnvelopeName + "\"}");
        Assert.Contains("8 MB", (await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, ""))).Message);

        _server.Reset();
        _server.Mode("short", 200, "{\"name\":\"" + EnvelopeName + "\"}");
        SigningflowException.ApiException ended = await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client(new Dictionary<string, object?> { ["retries"] = "0" }).Envelopes.RetrieveAsync(EnvelopeName, ""));
        Assert.Contains("declared length", ended.Message);
        Assert.DoesNotContain(EnvelopeName, ended.Message);

        _server.Reset();
        _server.Mode("redirect", 302, "");
        await Assert.ThrowsAnyAsync<SigningflowException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, ""));
        Assert.DoesNotContain(Hits(), hit => hit.Path == "/secret");

        _server.Reset();
        _server.Bytes(200, Gzip("{\"name\":\"" + EnvelopeName + "\"}"), "application/json", new Dictionary<string, string> { ["Content-Encoding"] = "gzip" });
        await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, ""));

        _server.Reset();
        _server.Bytes(200, Encoding.UTF8.GetBytes("not-json"), "application/octet-stream", new Dictionary<string, string>());
        Assert.Contains("non-JSON", (await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, ""))).Message);
    }

    [Fact]
    public async Task UploadRetriesAndRejectsEarlyStatus()
    {
        string upload = "https://127.0.0.1:" + _server.Port + "/bucket/a";
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"preSignedUrl\":\"" + upload + "\"}]}");
        _server.Json(500, "");
        _server.Json(200, "");
        _server.Json("{}");
        StoredFile stored = await Client().Files.CreateAsync(Encoding.UTF8.GetBytes("%PDF"), null, "a.pdf", "", "");
        Assert.Equal(StorageName, stored.Name);
        Assert.Equal(2, Hits().Count(hit => hit.Method == "PUT"));

        _server.Reset();
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(199, "");
        SigningflowException error = await Assert.ThrowsAnyAsync<SigningflowException>(() => Client(new Dictionary<string, object?> { ["retries"] = "0" }).Files.CreateAsync([1], null, "a.pdf", "application/pdf", ""));
        Assert.True(error is SigningflowException.ApiException or SigningflowException.ConnectionException);
        Assert.DoesNotContain(Hits(), hit => hit.Path.Contains("batchAcknowledgeUpload"));
    }

    [Fact]
    public async Task SendRecoveryAndErrors()
    {
        ScriptDraft();
        _server.Json(409, "{\"message\":\"idempotency key already used\",\"metadata\":{\"resource_id\":\"" + EnvelopeName + "\"}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"sent_time\":\"2020-01-01T00:00:00Z\"}");
        Envelope recovered = await Client().Envelopes.SendDocumentAsync("Contract", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], "");
        Assert.Equal(EnvelopeName, recovered.Name);

        _server.Reset();
        ScriptDraft();
        _server.Json(409, "{\"message\":\"conflict\"}");
        SigningflowException.InvalidRequestException conflict = await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.SendDocumentAsync("Contract", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""));
        Assert.Equal(EnvelopeName, conflict.EnvelopeName);

        _server.Reset();
        ScriptDraft();
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"sent_time\":\"2026-11-06T00:00:30Z\"}");
        Assert.Equal(EnvelopeName, (await Client().Envelopes.SendDocumentAsync("Contract", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], "")).Name);

        _server.Reset();
        ScriptDraft();
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"sent_time\":\"2020-01-01T00:00:00Z\"}");
        SigningflowException.ConnectionException old = await Assert.ThrowsAsync<SigningflowException.ConnectionException>(() => Client().Envelopes.SendDocumentAsync("Contract", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""));
        Assert.Equal(EnvelopeName, old.EnvelopeName);

        _server.Reset();
        ScriptDraft();
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"sent_time\":\"2099-01-01T00:00:00Z\"}");
        Assert.Equal(EnvelopeName, (await Assert.ThrowsAsync<SigningflowException.ConnectionException>(() => Client().Envelopes.SendDocumentAsync("Contract", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""))).EnvelopeName);

        _server.Reset();
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        await Assert.ThrowsAsync<SigningflowException.ConnectionException>(() => Client().Envelopes.SendAsync(EnvelopeName, ""));
        Assert.DoesNotContain(Hits(), hit => hit.Path.Contains(":view"));
    }

    [Fact]
    public async Task TemplateListDownloadAndWebhooks()
    {
        _server.Json("{\"envelope\":{\"uid\":\"11111111-1111-4111-8111-111111111111\",\"display_name\":\"From template\"}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"documents\":[{\"uid\":\"doc-1\",\"displayName\":\"From template\"}],\"compliance\":{}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"sentTime\":\"2026-11-06T00:00:00Z\"}");
        Envelope fromTemplate = await Client().Envelopes.SendFromTemplateAsync(TemplateName, [new Recipient("Ada", "ada@example.com")], "Hello");
        Assert.Equal(EnvelopeName, fromTemplate.Name);

        _server.Reset();
        _server.Json("{\"envelopes\":[{\"name\":\"" + EnvelopeName + "\"}],\"nextPageToken\":\"abc\"}");
        _server.Json("{\"envelopes\":[{\"name\":\"envelopes/33333333-3333-4333-8333-333333333333\"}],\"next_page_token\":\"abc\"}");
        var names = new List<string>();
        await foreach (Envelope item in (await Client().Envelopes.ListAsync("needAction", null, "", "name")).AllAsync())
        {
            names.Add(item.Name);
        }
        Assert.Equal([EnvelopeName, "envelopes/33333333-3333-4333-8333-333333333333"], names);

        _server.Reset();
        _server.PageForever = true;
        Page<Envelope> forever = await Client().Envelopes.ListAsync("waitingOthers", 10, null, "");
        await Assert.ThrowsAsync<Page<Envelope>.TooManyPagesException>(async () =>
        {
            await foreach (Envelope ignored in forever.AllAsync())
            {
            }
        });

        _server.Reset();
        _server.Json("{\"envelopes\":[],\"nextPageToken\":\"more\"}");
        _server.Json(500, "{\"message\":\"page failed\"}");
        Page<Envelope> first = await Client(new Dictionary<string, object?> { ["retries"] = "0" }).Envelopes.ListAsync("needAction", 1, null, "");
        await Assert.ThrowsAsync<Page<Envelope>.LoadException>(async () =>
        {
            await foreach (Envelope ignored in first.AllAsync())
            {
            }
        });

        _server.Reset();
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"progress\":{\"state\":\"completed\"}}");
        _server.Json("{\"uri\":\"https://files.example/a\",\"download_time\":\"2026-11-06T00:00:00Z\",\"etag\":\"abc\"}");
        Download download = await Client().Envelopes.DownloadCompletedAsync(EnvelopeName);
        Assert.Equal("https://files.example/a", download.Uri);
        Assert.Equal("abc", download.Etag);
        Assert.Equal(2, Hits().Count);

        _server.Reset();
        _server.Json("{\"name\":\"" + WebhookName + "\",\"displayName\":\"Hooks\",\"httpRequestUri\":\"https://example.com/hook\",\"events\":[\"DOC_ENVELOPE_COMPLETED\"],\"signingSecret\":\"whsec_once\"}");
        WebhookUrl created = await Client().WebhookUrls.CreateAsync("Hooks", "https://example.com/hook", ["DOC_ENVELOPE_COMPLETED"], null, "");
        Assert.Equal("whsec_once", created.SigningSecret);
        _server.Json("{\"name\":\"" + WebhookName + "\",\"signing_secret\":\"whsec_hidden\",\"signingSecret\":\"whsec_hidden\"}");
        Assert.Equal("", (await Client().WebhookUrls.RetrieveAsync(WebhookName)).SigningSecret);
        _server.Json("{\"name\":\"" + WebhookName + "\",\"signingSecret\":\"whsec_test\"}");
        Assert.Equal("whsec_test", (await Client().WebhookUrls.TestAsync(WebhookName)).SigningSecret);
        _server.Json("{\"webhooks\":[{\"name\":\"" + DeliveryName + "\",\"event\":\"DOC_ENVELOPE_COMPLETED\"}]}");
        Assert.Equal(DeliveryName, (await Client().WebhookDeliveries.ListAsync(null, null)).Data[0].Name);
        _server.Json("{\"name\":\"" + DeliveryName + "\",\"event\":\"DOC_ENVELOPE_COMPLETED\"}");
        Assert.Equal("DOC_ENVELOPE_COMPLETED", (await Client().WebhookDeliveries.RetrieveAsync(DeliveryName)).Event);
    }

    [Fact]
    public async Task WebhookAndInputGuards()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"event\":\"DOC_ENVELOPE_COMPLETED\"}");
        const string secret = "whsec_current";
        string signature = Mac(secret, body);
        Event constructed = Webhooks.ConstructEvent(body, signature.ToUpperInvariant(), secret, "", "");
        Assert.Equal("DOC_ENVELOPE_COMPLETED", Json.AsString(Json.AsMap(constructed.Payload)!.GetValueOrDefault("event")));
        Assert.Equal(Webhooks.BodySha256(body), constructed.BodySha256);
        string previous = Mac("whsec_old", body);
        Assert.Throws<SigningflowException.SignatureVerificationException>(() => Webhooks.ConstructEvent(body, "nope", "", "whsec_old", previous));
        Assert.Equal(constructed.BodySha256, Webhooks.ConstructEvent(body, "nope", secret, "whsec_old", previous).BodySha256);
        Assert.Throws<SigningflowException.SignatureVerificationException>(() => Webhooks.ConstructEvent(null, signature, secret, null, null));
        Assert.Throws<SigningflowException.SignatureVerificationException>(() => Webhooks.ConstructEvent(body, signature, "", null, null));
        Assert.Throws<SigningflowException.SignatureVerificationException>(() => Webhooks.ConstructEvent(body, "00", secret, "whsec_old", ""));
        byte[] broken = Encoding.UTF8.GetBytes("[");
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Webhooks.ConstructEvent(broken, Mac(secret, broken), secret, null, null));

        Assert.Contains("display_name", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("", "https://example.com", ["A"], null, ""))).Message);
        Assert.Contains("https", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("A", "http://example.com", ["A"], null, ""))).Message);
        Assert.Equal("events is required.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("A", "https://example.com", [], null, ""))).Message);
        Assert.Contains("NONE", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("A", "https://example.com", ["A"], new Dictionary<string, object?> { ["auth"] = "NONE" }, ""))).Message);
        Assert.Contains("HMAC", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("A", "https://example.com", ["A"], new Dictionary<string, object?> { ["auth"] = "BASIC" }, ""))).Message);
        Assert.Equal("idempotencyKey must be a UUID.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Files.CreateAsync([1], null, "a.pdf", "", "not-a-uuid"))).Message);
        Assert.Equal("Pass file bytes or a path, not both.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Files.CreateAsync([1], "a.pdf", "a.pdf", "", ""))).Message);
        Assert.Equal("Pass file bytes or a path.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Files.CreateAsync(null, "  ", "a.pdf", "", ""))).Message);
        Assert.Equal("filename is required when file is not a path.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Files.CreateAsync([1], null, " ", "", ""))).Message);
        Assert.Equal("invalid header value", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Files.CreateAsync([1], null, "a.pdf", "bad\nmime", ""))).Message);
        Assert.Equal("directory is required.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.ListAsync(" ", 10, null, ""))).Message);
        Assert.Equal("page_size must be from 1 to 1000.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.ListAsync("needAction", 0, null, ""))).Message);
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"state\":\"DRAFT\"}");
        Assert.Equal("The signed file is not ready.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.DownloadCompletedAsync(EnvelopeName))).Message);
        Assert.Equal("Unknown operation.", Assert.Throws<SigningflowException>(() => Allowlist.Require("nope")).Message);
    }

    [Fact]
    public async Task DefaultClientRejectsTheProbeCertificate()
    {
        SigningflowClient client = Client(new Dictionary<string, object?> { ["ca"] = "" });
        await Assert.ThrowsAsync<SigningflowException.ConnectionException>(() => client.Envelopes.RetrieveAsync(EnvelopeName, ""));
    }

    [Fact]
    public async Task ProxyListenerSeesNothing()
    {
        var proxy = new TcpListener(IPAddress.Loopback, 0);
        proxy.Start();
        IWebProxy previous = HttpClient.DefaultProxy;
        HttpClient.DefaultProxy = new WebProxy("http://127.0.0.1:" + ((IPEndPoint)proxy.LocalEndpoint).Port);
        try
        {
            _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
            Assert.Equal(EnvelopeName, (await Client().Envelopes.RetrieveAsync(EnvelopeName, "")).Name);
            await Task.Delay(200);
            Assert.False(proxy.Pending());
        }
        finally
        {
            HttpClient.DefaultProxy = previous;
            proxy.Stop();
        }
    }

    [Fact]
    public async Task StatusCodesAndRateLimitSleep()
    {
        _server.Json(401, "{\"message\":\"no\",\"code\":16}");
        Assert.IsType<SigningflowException.AuthenticationException>(await Assert.ThrowsAnyAsync<SigningflowException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, "")));
        _server.Json(403, "{\"message\":\"no\"}");
        Assert.IsType<SigningflowException.PermissionException>(await Assert.ThrowsAnyAsync<SigningflowException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, "")));
        _server.Json(429, "{\"message\":\"slow\"}");
        _server.Json(429, "{\"message\":\"slow\"}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        Assert.Equal(EnvelopeName, (await Client().Envelopes.RetrieveAsync(EnvelopeName, "")).Name);
        _server.Reset();
        _server.Bytes(429, Encoding.UTF8.GetBytes("{\"message\":\"slow\"}"), "application/json", new Dictionary<string, string> { ["Rate-Limit-Retry-After"] = "2099-01-01T00:00:00Z" });
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        var slept = new List<TimeSpan>();
        Clock.Delay = (span, _) =>
        {
            slept.Add(span);
            return Task.CompletedTask;
        };
        Clock.Now = () => Now;
        await Client(new Dictionary<string, object?> { ["retries"] = "1" }).Envelopes.RetrieveAsync(EnvelopeName, "");
        Assert.Equal(TimeSpan.FromSeconds(60), slept[0]);
        Assert.Equal(60, Urls.RetryDelay("2099-01-01T00:00:00Z", "", Now).TotalSeconds);
        Assert.Equal(0, Urls.RetryDelay("2", "", Now).TotalSeconds);
        Assert.Null(Urls.ParseTime("not-a-time"));
    }

    [Fact]
    public void JailRefusesLinksAndReadsARegularFile()
    {
        string root = Directory.CreateTempSubdirectory("signingflow-jail").FullName;
        string secret = Directory.CreateTempSubdirectory("signingflow-secret").FullName;
        try
        {
            File.WriteAllText(Path.Combine(root, "doc.pdf"), "%PDF");
            Assert.Equal(Encoding.UTF8.GetBytes("%PDF"), Jail.Read(root, "doc.pdf"));
            File.WriteAllBytes(Path.Combine(root, "empty.pdf"), []);
            Assert.Empty(Jail.Read(root, "empty.pdf"));
            File.WriteAllBytes(Path.Combine(root, "big.bin"), [1, 2]);
            Assert.Equal("The file is larger than 25 MB.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "big.bin", 1)).Message);
            Assert.Equal("A filesystem path requires upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(" ", "doc.pdf")).Message);
            Assert.Equal("The path is outside upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "/etc/passwd")).Message);
            Assert.Equal("The path is outside upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "../doc.pdf")).Message);
            Assert.Equal("The path is outside upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "")).Message);
            File.CreateSymbolicLink(Path.Combine(root, "link.pdf"), Path.Combine(root, "doc.pdf"));
            Assert.Equal("The file could not be read.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "link.pdf")).Message);
            Assert.Equal(0, Run("ln", Path.Combine(root, "doc.pdf"), Path.Combine(root, "hard.pdf")));
            Assert.Equal("The file must not be a hard link.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "doc.pdf")).Message);
            File.WriteAllText(Path.Combine(secret, "outside.txt"), "secret");
            Directory.CreateSymbolicLink(Path.Combine(root, "out"), secret);
            Assert.Equal("The path is outside upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "out/outside.txt")).Message);
            Assert.Equal(0, Run("mkfifo", Path.Combine(root, "fifo")));
            Assert.Equal("The file could not be read.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "fifo")).Message);
            AssertStatLayouts();
        }
        finally
        {
            DeleteTree(root);
            DeleteTree(secret);
        }
    }

    [Fact]
    public async Task CustomCaDoesNotWriteADebugFile()
    {
        const string debug = "/tmp/ssl-debug.txt";
        long before = File.Exists(debug) ? new FileInfo(debug).Length : -1;
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        Envelope viewed = await Client().Envelopes.RetrieveAsync(EnvelopeName, "");
        Assert.Equal(EnvelopeName, viewed.Name);
        SigningflowClient client = Client();
        object transport = typeof(SigningflowClient).GetField("_transport", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        MethodInfo validate = transport.GetType().GetMethod("Validate", BindingFlags.Instance | BindingFlags.NonPublic)!;
        object? accepted = validate.Invoke(transport, [new object(), null, null, SslPolicyErrors.RemoteCertificateNotAvailable]);
        Assert.Equal(false, accepted);
        long after = File.Exists(debug) ? new FileInfo(debug).Length : -1;
        Assert.Equal(before, after);
    }

    private static void AssertStatLayouts()
    {
        var mac = new byte[256];
        BinaryPrimitives.WriteUInt16LittleEndian(mac.AsSpan(4), 0x8124);
        BinaryPrimitives.WriteUInt16LittleEndian(mac.AsSpan(6), 1);
        BinaryPrimitives.WriteInt64LittleEndian(mac.AsSpan(96), 4);
        (int Mode, ulong Links, long Size) macOs = Jail.DecodeStat(mac, true, false, Architecture.Arm64);
        Assert.Equal(0x8124, macOs.Mode);
        Assert.Equal(1UL, macOs.Links);
        Assert.Equal(4, macOs.Size);

        var arm = new byte[256];
        BinaryPrimitives.WriteInt32LittleEndian(arm.AsSpan(16), 0x8000);
        BinaryPrimitives.WriteUInt32LittleEndian(arm.AsSpan(20), 3);
        BinaryPrimitives.WriteInt64LittleEndian(arm.AsSpan(40), 11);
        (int Mode, ulong Links, long Size) arm64 = Jail.DecodeStat(arm, false, true, Architecture.Arm64);
        Assert.Equal(0x8000, arm64.Mode);
        Assert.Equal(3UL, arm64.Links);
        Assert.Equal(11, arm64.Size);

        var x64 = new byte[256];
        BinaryPrimitives.WriteUInt64LittleEndian(x64.AsSpan(16), 1);
        BinaryPrimitives.WriteInt32LittleEndian(x64.AsSpan(24), 0x8000);
        BinaryPrimitives.WriteInt64LittleEndian(x64.AsSpan(48), 7);
        (int Mode, ulong Links, long Size) linux = Jail.DecodeStat(x64, false, true, Architecture.X64);
        Assert.Equal(0x8000, linux.Mode);
        Assert.Equal(1UL, linux.Links);
        Assert.Equal(7, linux.Size);

        Assert.Throws<IOException>(() => Jail.DecodeStat(new byte[256], false, true, Architecture.X86));
        Assert.Throws<IOException>(() => Jail.DecodeStat(new byte[256], false, false, Architecture.X64));
    }

    [Fact]
    public async Task PathUploadAndJsonUrls()
    {
        string root = Directory.CreateTempSubdirectory("signingflow-upload").FullName;
        try
        {
            File.WriteAllBytes(Path.Combine(root, "empty.pdf"), []);
            string upload = "https://127.0.0.1:" + _server.Port + "/bucket/a";
            _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
            _server.Json(200, "");
            _server.Json("{}");
            StoredFile stored = await Client(new Dictionary<string, object?> { ["root"] = root }).Files.CreateAsync(null, "empty.pdf", "", "text/plain", "11111111-1111-4111-8111-111111111111");
            Assert.Equal(StorageName, stored.Name);
            Assert.Contains("\"size\":\"0\"", Hits()[0].Text());
        }
        finally
        {
            DeleteTree(root);
        }

        Dictionary<string, object?> decoded = Json.AsMap(Json.Read("{\"n\":1,\"f\":1.5,\"ok\":true,\"no\":null,\"s\":\"a\\nb\",\"list\":[1]}"))!;
        Assert.Equal(1, Json.AsInt(decoded["n"]));
        Assert.Equal(1, Json.AsInt(decoded["f"]));
        Assert.Null(Json.AsInt(decoded["ok"]));
        Assert.Null(Json.AsInt(false));
        Assert.Equal("", Json.AsString(1));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("{"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("{\"a\":1} trailing"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Json.Write(double.NaN));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Json.Write(new object()));
        Assert.Equal("https://api.signingflow.com/v1/envelopes/abc", Urls.Resolve("https://api.signingflow.com", "/v1/envelopes/abc", new Dictionary<string, string> { ["pageToken"] = "" }));
        Assert.Equal("[::1]", Urls.HostOf(new Uri("https://[::1]/v1")));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl("http://storage.googleapis.com/a", ["storage.googleapis.com"]));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl("https://user@storage.googleapis.com/a", ["storage.googleapis.com"]));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl("https://evil.com/a", ["storage.googleapis.com"]));
        Uri allowed = Urls.AllowedUploadUrl("https://bucket.storage.googleapis.com/a#@evil.com", ["storage.googleapis.com"]);
        Assert.Equal("bucket.storage.googleapis.com", Urls.HostOf(allowed));
        Assert.Equal("upload host rejected", Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl("https://notstorage.googleapis.com/a", ["storage.googleapis.com"])).Message);
        Assert.EndsWith("…", Redact.Message(new string('x', 600), ""));
        Assert.Equal("df_sk_redacted", Redact.Text("df_sk_plain", ""));
    }

    private void ScriptDraft()
    {
        string upload = "https://127.0.0.1:" + _server.Port + "/bucket/a";
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(200, "");
        _server.Json("{}");
        _server.Json("{\"envelope\":{\"name\":\"" + EnvelopeName + "\"}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"documents\":[{\"uid\":\"doc-1\",\"display_name\":\"Contract\"}]}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
    }

    private SigningflowClient Client(Dictionary<string, object?>? overrides = null)
    {
        overrides ??= new Dictionary<string, object?>();
        string key = overrides.TryGetValue("key", out object? keyValue) ? (string)keyValue! : "df_sk_test";
        string workspace = overrides.TryGetValue("workspace", out object? workspaceValue) ? (string)workspaceValue! : "ws";
        string baseUrl = overrides.TryGetValue("base", out object? baseValue) ? (string)baseValue! : "https://127.0.0.1:" + _server.Port;
        bool custom = overrides.TryGetValue("custom", out object? customValue)
            ? customValue is true
            : !baseUrl.Contains("api.signingflow.com", StringComparison.OrdinalIgnoreCase);
        var hosts = overrides.TryGetValue("hosts", out object? hostValue) ? (IReadOnlyList<string>)hostValue! : new List<string> { "127.0.0.1" };
        var client = new SigningflowClient(key, ClientOptions.NewBuilder()
            .WorkspaceId(workspace)
            .Env(overrides.TryGetValue("env", out object? env) ? (string)env! : "sandbox")
            .BaseUrl(baseUrl)
            .AllowCustomBaseUrl(custom)
            .Timeout(TimeSpan.FromMilliseconds(long.Parse((overrides.TryGetValue("timeout", out object? timeout) ? timeout : "2000")!.ToString()!)))
            .MaxNetworkRetries(int.Parse((overrides.TryGetValue("retries", out object? retries) ? retries : "2")!.ToString()!))
            .UploadHosts(hosts)
            .Channel(overrides.TryGetValue("channel", out object? channel) ? (string)channel! : "")
            .Funnel(overrides.TryGetValue("funnel", out object? funnel) ? (string)funnel! : "")
            .UploadRoot(overrides.TryGetValue("root", out object? root) ? (string)root! : "")
            .CaBundle(overrides.TryGetValue("ca", out object? ca) ? (string)ca! : _server.Certificate)
            .Build());
        _clients.Add(client);
        return client;
    }

    private List<LocalTls.Hit> Hits()
    {
        lock (_server.Hits)
        {
            return _server.Hits.ToList();
        }
    }

    private static byte[] Gzip(string text)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(text));
        }
        return output.ToArray();
    }

    private static string Mac(string secret, byte[] body)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(body)).ToLowerInvariant();
    }

    private static string JsonEscape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"");

    private static int Run(string file, params string[] args)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file, args) { RedirectStandardError = true });
        process!.WaitForExit();
        return process.ExitCode;
    }

    private static void DeleteTree(string root)
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, true);
        }
    }
}
