using System.IO.Compression;
using System.Text;
using Xunit;

namespace Signingflow.Tests;

[Collection("tls")]
public sealed class CoverageTests : IDisposable
{
    private const string EnvelopeName = "envelopes/11111111-1111-4111-8111-111111111111";
    private const string StorageName = "storages/22222222-2222-4222-8222-222222222222";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-06T00:00:00Z");

    private readonly LocalTls _server;
    private readonly List<SigningflowClient> _clients = [];

    public CoverageTests(TlsFixture fixture)
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
    public async Task ClockSleepsOnlyForAPositiveDelay()
    {
        Clock.Reset();
        await Clock.PauseAsync(TimeSpan.Zero);
        await Clock.PauseAsync(TimeSpan.FromMilliseconds(-1));
        await Clock.PauseAsync(TimeSpan.FromMilliseconds(1));
        Assert.True(Clock.Instant() > DateTimeOffset.UnixEpoch);
    }

    [Fact]
    public void JsonCoversScalarsEscapesAndRejections()
    {
        object? decoded = Json.Read(" { \"a\" : [ true, false, null, -2, 0, 1.5, 2e1, \"x\\/\\b\\f\\n\\r\\t\\u0041\" ] } ");
        List<object?> list = (List<object?>)Json.AsMap(decoded)!["a"]!;
        Assert.Equal(true, list[0]);
        Assert.Equal(false, list[1]);
        Assert.Null(list[2]);
        Assert.Equal(-2L, list[3]);
        Assert.Equal(20.0, (double)list[6]!);
        Assert.Equal("x/\b\f\n\r\tA", list[7]);
        Assert.Equal("{\"a\":1}", Json.Write(new Dictionary<string, object?> { ["a"] = 1 }));
        Assert.Equal("[1]", Json.Write(new List<object?> { 1 }));
        Assert.Equal("\"\\u0001\"", Json.Write("\u0001"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read(null));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read(""));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("tru"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("nul"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("\"\\q\""));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("\"\\u12\""));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("\"\\u12zz\""));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("\"\u0001\""));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("{"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("{\"a\"}"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("[1,]"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("-"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("1."));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("1e"));
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read("01"));
        Assert.Equal(1L, Json.Read("1"));
        Assert.Null(Json.AsInt(long.MaxValue));
        Assert.Equal(12, Json.AsInt("12"));
        Assert.Null(Json.AsInt("nope"));
        Assert.Null(Json.AsMap(new List<object?>()));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Json.Write(new Dictionary<int, string> { [1] = "a" }));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Json.Write(double.PositiveInfinity));
        object nested = new Dictionary<string, object?>();
        for (int i = 0; i < 40; i++)
        {
            nested = new Dictionary<string, object?> { ["a"] = nested };
        }
        object tooDeep = nested;
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Json.Write(tooDeep));
        Assert.Equal(2, Json.AsInt(2.9));
        var deep = new StringBuilder();
        deep.Append("{\"a\":".PadRight(0));
        for (int i = 0; i < 40; i++)
        {
            deep.Append("{\"a\":");
        }
        deep.Append('1');
        deep.Append('}', 40);
        Assert.Throws<SigningflowException.ApiException>(() => Json.Read(deep.ToString()));
    }

    [Fact]
    public void UrlsCoverHostsQueriesAndDelays()
    {
        Assert.Equal("/v1/envelopes/abc:view", Urls.Fill("/v1/{name_1}:view", new Dictionary<string, string> { ["name"] = "envelopes/abc" }));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Fill("/v1/{name}", new Dictionary<string, string>()));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Fill("/v1/{name}", new Dictionary<string, string> { ["name"] = "a/../b" }));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Fill("/v1/{", new Dictionary<string, string>()));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Resolve("https://api.signingflow.com", "v1", new Dictionary<string, string>()));
        Assert.Equal("", Urls.Encode(null));
        Assert.Equal("a=b", Urls.Encode(new Dictionary<string, string> { ["a"] = "b", ["empty"] = "" }));
        Assert.True(Urls.ContainsSecret("a=" + Urls.Rfc3986("df_sk_a/b c+"), "df_sk_a/b c+"));
        Assert.True(Urls.ContainsSecret("a=" + Redact.FormEncode("df_sk_a/b c+"), "df_sk_a/b c+"));
        Assert.True(Urls.ContainsSecret("a=%", "df_sk_test"));
        Assert.True(Urls.ContainsSecret("a=%zz", "df_sk_test"));
        Assert.False(Urls.ContainsSecret("a=b", ""));
        Assert.False(Urls.ContainsSecret("directory=needAction", "df_sk_test"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl(null, ["storage.googleapis.com"]));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl("https://storage.googleapis.com.\u0000/a", ["storage.googleapis.com"]));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.AllowedUploadUrl("https://storage.googleapis.com./a", ["storage.googleapis.com"]));
        Assert.Equal("BUCKET.storage.googleapis.com", Urls.HostOf(Urls.AllowedUploadUrl("https://BUCKET.storage.googleapis.com/a", ["storage.googleapis.com"])));
        Assert.Equal(TimeSpan.Zero, Urls.RetryDelay("2020-01-01T00:00:00Z", "", Now));
        Assert.Equal(TimeSpan.FromSeconds(30), Urls.RetryDelay("", "2026-11-06T00:00:30Z", Now));
        Assert.Equal(TimeSpan.Zero, Urls.RetryDelay("not", "also", Now));
        Assert.Null(Urls.ParseTime(null));
        Assert.Null(Urls.ParseTime("  "));
        Assert.Equal(Now, Urls.ParseTime("2026-11-06T00:00:00"));
        Assert.Equal(Now, Urls.ParseTime("2026-11-06T00:00:00+00:00"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.HostOf(new Uri("https://user@api.signingflow.com/")));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Parse(null));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Parse("https://api.signingflow.com/\u0000"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Urls.Parse("not a url"));
        Assert.Equal("api.signingflow.com", Urls.HostOf(new Uri("https://api.signingflow.com:444/v1")));
        Assert.Equal("?token=[redacted]&sig=[redacted]", Redact.Text("?token=abc&sig=def", ""));
        Assert.Empty(Redact.Violations(null, "df_sk_test"));
        _ = new SigningflowException("x", 1, null, null, null, null, null, null, null, null, null);
        _ = new SigningflowException.FieldViolation(null, null);
    }

    [Fact]
    public void OptionsAndModelsCoverRejections()
    {
        ClientOptions custom = ClientOptions.NewBuilder()
            .WorkspaceId(" ws ")
            .Env("live")
            .BaseUrl("https://files.example.com")
            .AllowCustomBaseUrl(true)
            .UploadHosts([" files.example.com ", "", "a.b.example"])
            .Build();
        Assert.Equal("LIVE", custom.WireEnv);
        Assert.Equal(["files.example.com", "a.b.example"], custom.UploadHosts);
        Assert.Throws<SigningflowException.InvalidRequestException>(() => ClientOptions.NewBuilder().WorkspaceId("ws").Env("sandbox").UploadHosts(["a..b.com"]).Build());
        Assert.Throws<SigningflowException.InvalidRequestException>(() => ClientOptions.NewBuilder().WorkspaceId("ws").Env("sandbox").UploadHosts(["example.com."]).Build());
        Assert.Throws<SigningflowException.InvalidRequestException>(() => ClientOptions.NewBuilder().WorkspaceId("a\nb").Env("sandbox").Build());
        Assert.Throws<SigningflowException.InvalidRequestException>(() => new SigningflowClient("df_sk_test", ClientOptions.NewBuilder().WorkspaceId("ws").Env("sandbox").Funnel("a\u0000b").Build()));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => ClientOptions.NewBuilder().WorkspaceId("ws").Env("sandbox").Timeout(TimeSpan.FromMilliseconds(-1)).Build());
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Models.EnvelopeName("nope"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Models.TemplateName("templates/nope"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Models.WebhookName("webhook/1"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Models.DeliveryName("webhooks/nope"));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Models.CleanRecipients(null));
        Assert.Throws<SigningflowException.InvalidRequestException>(() => Models.CleanRecipients([new Recipient("Ada", "not-an-email")]));
        Envelope decoded = Models.Decode(new Dictionary<string, object?>
        {
            ["envelope"] = new Dictionary<string, object?>
            {
                ["uid"] = "11111111-1111-4111-8111-111111111111",
                ["documents"] = new List<object?> { "skip", new Dictionary<string, object?> { ["uid"] = "doc" } },
            },
        });
        Assert.Single(decoded.Documents);
        Assert.Equal(EnvelopeName, Models.NameOf(new Dictionary<string, object?> { ["uid"] = "11111111-1111-4111-8111-111111111111" }));
        Assert.Equal("", Models.NameOf("nope"));
        Assert.Null(Models.FindStorage(new Dictionary<string, object?>
        {
            ["storages"] = new List<object?> { new Dictionary<string, object?> { ["name"] = "storages/not-a-uuid", ["pre_signed_url"] = "https://example.com" } },
        }));
        Assert.Equal(StorageName, Models.FindStorage(new List<object?> { new Dictionary<string, object?> { ["name"] = StorageName, ["preSignedUrl"] = "https://example.com/a" } })![0]);
        string root = Directory.CreateTempSubdirectory("signingflow-more").FullName;
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "dir"));
            Assert.Equal("The file could not be read.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "dir")).Message);
            Assert.Equal("The file could not be read.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "missing.pdf")).Message);
            Assert.Equal("The path is outside upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, ".")).Message);
            Assert.Equal("The path is outside upload_root.", Assert.Throws<SigningflowException.InvalidRequestException>(() => Jail.Read(root, "a\u0000b")).Message);
        }
        finally
        {
            Directory.Delete(root, true);
        }
        Assert.Equal("Unknown operation.", Assert.Throws<SigningflowException>(() => Allowlist.Require("")).Message);
        Assert.Equal("POST", Allowlist.Require("EnvelopeService_AddEnvelope").Http);
    }

    [Fact]
    public async Task MoreApiBranches()
    {
        SigningflowClient api = Client(new Dictionary<string, object?> { ["channel"] = "desk", ["funnel"] = "mail" });
        _server.Json("");
        Envelope empty = await api.Envelopes.RetrieveAsync(EnvelopeName, "");
        Assert.Equal(EnvelopeName, empty.Name);
        Assert.Equal("desk", Hits()[0].Header("x-request-channel"));
        Assert.Equal("mail", Hits()[0].Header("x-request-funnel"));

        _server.Reset();
        _server.Bytes(200, Gzip("hello"), "text/plain", new Dictionary<string, string>());
        await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client().Envelopes.RetrieveAsync(EnvelopeName, ""));

        _server.Reset();
        _server.Json(408, "{\"message\":\"again\"}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        Assert.Equal(EnvelopeName, (await Client().Envelopes.RetrieveAsync(EnvelopeName, "name")).Name);

        _server.Reset();
        _server.Json(429, "{\"message\":\"slow\"}");
        await Assert.ThrowsAsync<SigningflowException.RateLimitException>(() => Client(new Dictionary<string, object?> { ["retries"] = "0" }).Envelopes.RetrieveAsync(EnvelopeName, ""));

        string upload = "https://127.0.0.1:" + _server.Port + "/bucket/a";
        _server.Reset();
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(200, "");
        _server.Json("{}");
        _server.Json("{\"ok\":true}");
        Assert.Contains("envelope name", (await Assert.ThrowsAsync<SigningflowException.ApiException>(() => Client().Envelopes.SendDocumentAsync("Title", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""))).Message);

        _server.Reset();
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(200, "");
        _server.Json("{}");
        _server.Json("{\"envelope\":{\"name\":\"" + EnvelopeName + "\"}}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"documents\":[]}");
        Assert.Equal("The draft has no document to address.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.SendDocumentAsync("Title", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""))).Message);

        _server.Reset();
        ScriptDraft();
        _server.Json(400, "{\"message\":\"bad patch\"}");
        Assert.Equal(EnvelopeName, (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.SendDocumentAsync("Title", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""))).EnvelopeName);

        _server.Reset();
        ScriptDraft();
        _server.Json(409, "{\"message\":\"idempotency used\",\"metadata\":{\"resource_id\":\"envelopes/other\"}}");
        Assert.Equal(EnvelopeName, (await Assert.ThrowsAsync<SigningflowException.IdempotencyException>(() => Client().Envelopes.SendDocumentAsync("Title", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""))).EnvelopeName);

        _server.Reset();
        ScriptDraft();
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Mode("drop", 0, "");
        _server.Json(500, "{\"message\":\"view failed\"}");
        Assert.Equal(EnvelopeName, (await Assert.ThrowsAsync<SigningflowException.ConnectionException>(() => Client().Envelopes.SendDocumentAsync("Title", [1], null, "a.pdf", [new Recipient("Ada", "ada@example.com")], ""))).EnvelopeName);

        _server.Reset();
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        Assert.Equal(EnvelopeName, (await Client().Envelopes.UpdateAsync(EnvelopeName, new Dictionary<string, object?>())).Name);
        _server.Json("{\"uri\":\"https://files.example/a\",\"downloadTime\":\"2026-11-06T00:00:00Z\",\"etag\":\"e\"}");
        Assert.Equal("e", (await Client().Envelopes.DownloadAsync(EnvelopeName)).Etag);
        _server.Json("{\"name\":\"" + EnvelopeName + "\"}");
        Assert.Equal(EnvelopeName, (await Client().Envelopes.RemindAsync(EnvelopeName)).Name);

        _server.Reset();
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(200, "");
        _server.Json("{}");
        _server.Json("{\"name\":\"" + EnvelopeName + "\",\"display_name\":\"Draft\"}");
        Assert.Equal(EnvelopeName, (await Client().Envelopes.PrepareDraftAsync("Draft", [1], null, "draft.pdf", "note")).Name);

        _server.Reset();
        await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync(new string('x', 101), "https://example.com", ["A"], null, ""));
        await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("Hooks", "://", ["A"], null, ""));
        await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("Hooks", "https://example.com", null, null, ""));
        Assert.Contains("NONE", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookUrls.CreateAsync("Hooks", "https://example.com", ["A"], "NONE", ""))).Message);
        Assert.Equal("", WebhookUrls.SigningSecretOf("nope"));
        Assert.Equal("", WebhookUrls.SigningSecretOf(new WebhookUrl("", "", "", [], "")));
        _server.Json("{\"webhooks\":[\"skip\",{\"name\":\"webhooks/11111111-1111-4111-8111-111111111111\",\"event\":\"A\"}],\"nextPageToken\":\"\"}");
        Assert.Single((await Client().WebhookDeliveries.ListAsync(1000, "")).Data);
        await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().WebhookDeliveries.ListAsync(1001, null));
        await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.CreateAsync("Title", "", "", ""));
        Assert.Equal("127.0.0.1", Urls.HostOf(Urls.AllowedUploadUrl("https://127.0.0.1:" + _server.Port + "/a", ["127.0.0.1"])));
        _server.Json("{\"storages\":[{\"name\":\"" + StorageName + "\",\"pre_signed_url\":\"" + upload + "\"}]}");
        _server.Json(200, "");
        _server.Json("{}");
        StoredFile notes = await Client().Files.CreateAsync([], null, "notes.txt", "", "11111111-1111-4111-8111-111111111111");
        Assert.Equal(StorageName, notes.Name);
        Assert.Contains("text/plain", Hits()[^3].Text());
        Assert.Equal("Name the draft title.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.CreateAsync(" ", "", StorageName, ""))).Message);
        Assert.Equal("Each recipient needs a name and an email.", (await Assert.ThrowsAsync<SigningflowException.InvalidRequestException>(() => Client().Envelopes.SendDocumentAsync("Title", [1], null, "a.pdf", [new Recipient("", "ada@example.com")], ""))).Message);
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
        string baseUrl = overrides.TryGetValue("base", out object? baseValue) ? (string)baseValue! : "https://127.0.0.1:" + _server.Port;
        bool custom = !baseUrl.Contains("api.signingflow.com", StringComparison.OrdinalIgnoreCase);
        var client = new SigningflowClient("df_sk_test", ClientOptions.NewBuilder()
            .WorkspaceId("ws")
            .Env("sandbox")
            .BaseUrl(baseUrl)
            .AllowCustomBaseUrl(custom)
            .Timeout(TimeSpan.FromMilliseconds(2000))
            .MaxNetworkRetries(overrides.TryGetValue("retries", out object? retries) ? int.Parse(retries!.ToString()!) : 2)
            .UploadHosts(["127.0.0.1"])
            .Channel(overrides.TryGetValue("channel", out object? channel) ? (string)channel! : "")
            .Funnel(overrides.TryGetValue("funnel", out object? funnel) ? (string)funnel! : "")
            .CaBundle(_server.Certificate)
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
}
