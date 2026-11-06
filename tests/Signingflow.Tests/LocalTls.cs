using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Signingflow.Tests;

public sealed class LocalTls : IDisposable
{
    private readonly TcpListener _listen;
    private readonly X509Certificate2 _certificate;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentQueue<Reply> _replies = new();
    private readonly Task _accept;
    private int _pages;

    private LocalTls(TcpListener listen, X509Certificate2 certificate, string pemPath)
    {
        _listen = listen;
        _certificate = certificate;
        Certificate = pemPath;
        Port = ((IPEndPoint)listen.LocalEndpoint).Port;
        _accept = Task.Run(AcceptLoop);
    }

    public int Port { get; }
    public string Certificate { get; }
    public List<Hit> Hits { get; } = [];
    public bool PageForever { get; set; }

    public static LocalTls Start()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=127.0.0.1", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, false));
        using X509Certificate2 generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        var certificate = new X509Certificate2(generated.Export(X509ContentType.Pfx, "changeit"), "changeit", X509KeyStorageFlags.Exportable);
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("The probe certificate has no private key.");
        }
        string directory = Path.Combine(Path.GetTempPath(), "signingflow-dotnet-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string pem = Path.Combine(directory, "probe.pem");
        File.WriteAllText(pem, certificate.ExportCertificatePem());
        var listen = new TcpListener(IPAddress.Loopback, 0);
        listen.Start();
        return new LocalTls(listen, certificate, pem);
    }

    public void Reset()
    {
        lock (Hits)
        {
            Hits.Clear();
        }
        while (_replies.TryDequeue(out _))
        {
        }
        PageForever = false;
        Interlocked.Exchange(ref _pages, 0);
    }

    public void Json(int status, string body) =>
        _replies.Enqueue(new Reply(status, Encoding.UTF8.GetBytes(body), "application/json", "normal", new Dictionary<string, string>()));

    public void Json(string body) => Json(200, body);

    public void Mode(string mode, int status, string body) =>
        _replies.Enqueue(new Reply(status, Encoding.UTF8.GetBytes(body), "application/json", mode, new Dictionary<string, string>()));

    public void Bytes(int status, byte[] body, string type, IReadOnlyDictionary<string, string> headers) =>
        _replies.Enqueue(new Reply(status, body, type, "normal", new Dictionary<string, string>(headers)));

    public void Dispose()
    {
        _stop.Cancel();
        _listen.Stop();
        try
        {
            _accept.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
        }
        _certificate.Dispose();
        _stop.Dispose();
    }

    private async Task AcceptLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listen.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception)
            {
                return;
            }
            _ = Task.Run(() => Handle(client));
        }
    }

    private async Task Handle(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.ReceiveTimeout = 4000;
                client.SendTimeout = 4000;
                await using NetworkStream raw = client.GetStream();
                await using var ssl = new SslStream(raw, leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                });
                byte[] headerBytes = await ReadHeaders(ssl);
                string header = Encoding.Latin1.GetString(headerBytes);
                string[] lines = header.Split("\r\n");
                string[] request = lines[0].Split(' ');
                if (request.Length < 2)
                {
                    return;
                }
                string target = request[1];
                int queryAt = target.IndexOf('?');
                string path = queryAt < 0 ? target : target[..queryAt];
                string query = queryAt < 0 ? "" : target[(queryAt + 1)..];
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 1; i < lines.Length; i++)
                {
                    int colon = lines[i].IndexOf(':');
                    if (colon > 0)
                    {
                        headers[lines[i][..colon].Trim()] = lines[i][(colon + 1)..].Trim();
                    }
                }
                int length = 0;
                if (headers.TryGetValue("content-length", out string? declared) && declared.All(char.IsAsciiDigit))
                {
                    length = int.Parse(declared, System.Globalization.CultureInfo.InvariantCulture);
                }
                byte[] body = await ReadExact(ssl, length);
                lock (Hits)
                {
                    Hits.Add(new Hit(request[0], path, query, headers, body));
                }
                Reply reply;
                if (PageForever)
                {
                    reply = Page();
                }
                else if (!_replies.TryDequeue(out reply!))
                {
                    reply = new Reply(200, Encoding.UTF8.GetBytes("{}"), "application/json", "normal", new Dictionary<string, string>());
                }
                if (reply.Mode == "drop")
                {
                    return;
                }
                if (reply.Mode == "stall")
                {
                    await Task.Delay(3000);
                }
                if (reply.Mode == "redirect")
                {
                    string redirect = "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:" + Port + "/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    await ssl.WriteAsync(Encoding.ASCII.GetBytes(redirect));
                    return;
                }
                var head = new StringBuilder();
                head.Append("HTTP/1.1 ").Append(reply.Status).Append(" X\r\n");
                if (reply.Mode == "huge")
                {
                    head.Append("Content-Type: application/json\r\nContent-Length: 20000000\r\nConnection: close\r\n\r\n");
                    await ssl.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()));
                    await ssl.WriteAsync(reply.Body);
                    return;
                }
                if (reply.Mode == "short")
                {
                    head.Append("Content-Type: application/json\r\nContent-Length: 80\r\nConnection: close\r\n\r\n");
                    await ssl.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()));
                    await ssl.WriteAsync(reply.Body);
                    return;
                }
                head.Append("Content-Type: ").Append(reply.Type).Append("\r\n");
                foreach (KeyValuePair<string, string> extra in reply.Headers)
                {
                    head.Append(extra.Key).Append(": ").Append(extra.Value).Append("\r\n");
                }
                head.Append("Content-Length: ").Append(reply.Body.Length).Append("\r\nConnection: close\r\n\r\n");
                await ssl.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()));
                await ssl.WriteAsync(reply.Body);
            }
            catch (Exception)
            {
            }
        }
    }

    private Reply Page()
    {
        int n = Interlocked.Increment(ref _pages);
        string body = "{\"envelopes\":[{\"name\":\"envelopes/11111111-1111-4111-8111-111111111111\"}],\"nextPageToken\":\"page-" + n + "\"}";
        return new Reply(200, Encoding.UTF8.GetBytes(body), "application/json", "normal", new Dictionary<string, string>());
    }

    private static async Task<byte[]> ReadHeaders(Stream stream)
    {
        using var output = new MemoryStream();
        int a = 0;
        int b = 0;
        int c = 0;
        var one = new byte[1];
        while (true)
        {
            int read = await stream.ReadAsync(one);
            if (read <= 0)
            {
                throw new EndOfStreamException();
            }
            output.WriteByte(one[0]);
            if (a == '\r' && b == '\n' && c == '\r' && one[0] == '\n')
            {
                return output.ToArray();
            }
            a = b;
            b = c;
            c = one[0];
            if (output.Length > 65536)
            {
                throw new IOException("headers too large");
            }
        }
    }

    private static async Task<byte[]> ReadExact(Stream stream, int length)
    {
        var body = new byte[length];
        int filled = 0;
        while (filled < length)
        {
            int read = await stream.ReadAsync(body.AsMemory(filled));
            if (read <= 0)
            {
                break;
            }
            filled += read;
        }
        return body;
    }

    private sealed record Reply(int Status, byte[] Body, string Type, string Mode, Dictionary<string, string> Headers);

    public sealed record Hit(string Method, string Path, string Query, Dictionary<string, string> Headers, byte[] Body)
    {
        public string Header(string name) => Headers.TryGetValue(name, out string? value) ? value : "";
        public string Text() => Encoding.UTF8.GetString(Body);
    }
}

[CollectionDefinition("tls")]
public sealed class TlsCollection : ICollectionFixture<TlsFixture>
{
}

public sealed class TlsFixture : IDisposable
{
    public TlsFixture() => Server = LocalTls.Start();
    public LocalTls Server { get; }
    public void Dispose() => Server.Dispose();
}
