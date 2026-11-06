using System.Globalization;

namespace Signingflow;

public sealed class ClientOptions
{
    public const string DefaultBaseUrl = "https://api.signingflow.com";

    private ClientOptions(Builder builder)
    {
        WorkspaceId = builder.WorkspaceValue?.Trim() ?? "";
        if (WorkspaceId.Length == 0)
        {
            throw new SigningflowException.InvalidRequestException("workspace_id is required.");
        }
        WireEnv = Wire(builder.EnvValue);
        string baseUrl = string.IsNullOrWhiteSpace(builder.BaseUrlValue) ? DefaultBaseUrl : builder.BaseUrlValue.Trim();
        while (baseUrl.EndsWith('/'))
        {
            baseUrl = baseUrl[..^1];
        }
        Uri uri = Urls.Parse(baseUrl);
        if (uri.Scheme != "https")
        {
            throw new SigningflowException.InvalidRequestException("base_url must be https.");
        }
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new SigningflowException.InvalidRequestException("base_url must not include a username or password.");
        }
        string host = Urls.HostOf(uri);
        if (!Urls.OfficialHost.Equals(host, StringComparison.Ordinal) && !builder.AllowCustomBaseUrlValue)
        {
            throw new SigningflowException.InvalidRequestException("base_url host must be api.signingflow.com, or set allow_custom_base_url.");
        }
        BaseUrl = baseUrl;
        AllowCustomBaseUrl = builder.AllowCustomBaseUrlValue;
        if (builder.TimeoutValue <= TimeSpan.Zero)
        {
            throw new SigningflowException.InvalidRequestException("timeout must be positive.");
        }
        Timeout = builder.TimeoutValue;
        if (builder.MaxNetworkRetriesValue < 0)
        {
            throw new SigningflowException.InvalidRequestException("max_network_retries must be a whole number of zero or more.");
        }
        MaxNetworkRetries = builder.MaxNetworkRetriesValue;
        UploadHosts = CleanHosts(builder.UploadHostsValue);
        Channel = builder.ChannelValue?.Trim() ?? "";
        Funnel = builder.FunnelValue?.Trim() ?? "";
        if (BadHeader(WorkspaceId) || BadHeader(Channel) || BadHeader(Funnel))
        {
            throw new SigningflowException.InvalidRequestException("invalid header value");
        }
        UploadRoot = builder.UploadRootValue?.Trim() ?? "";
        CaBundle = builder.CaBundleValue?.Trim() ?? "";
    }

    public string WorkspaceId { get; }
    public string WireEnv { get; }
    public string BaseUrl { get; }
    public bool AllowCustomBaseUrl { get; }
    public TimeSpan Timeout { get; }
    public int MaxNetworkRetries { get; }
    public IReadOnlyList<string> UploadHosts { get; }
    public string Channel { get; }
    public string Funnel { get; }
    public string UploadRoot { get; }
    public string CaBundle { get; }

    public static Builder NewBuilder() => new();

    internal static bool BadHeader(string? value) =>
        value != null && (value.Contains('\r') || value.Contains('\n') || value.Contains('\0'));

    private static string Wire(string? env)
    {
        if (env == "sandbox" || env == "SANDBOX")
        {
            return "SANDBOX";
        }
        if (env == "live" || env == "LIVE")
        {
            return "LIVE";
        }
        throw new SigningflowException.InvalidRequestException("env must be sandbox or live.");
    }

    private static IReadOnlyList<string> CleanHosts(IReadOnlyList<string>? hosts)
    {
        IReadOnlyList<string> source = hosts ?? ["storage.googleapis.com"];
        var cleaned = new List<string>();
        foreach (string host in source)
        {
            string value = host == null ? "" : host.Trim().ToLower(CultureInfo.InvariantCulture);
            if (value.Length == 0)
            {
                continue;
            }
            int dots = value.Count(character => character == '.');
            if (dots < 2 || value.StartsWith('.') || value.EndsWith('.') || value.Contains("..", StringComparison.Ordinal))
            {
                throw new SigningflowException.InvalidRequestException("Each upload_hosts entry must be a specific host, not a public suffix.");
            }
            cleaned.Add(value);
        }
        return cleaned;
    }

    public sealed class Builder
    {
        internal string? WorkspaceValue;
        internal string? EnvValue;
        internal string? BaseUrlValue;
        internal bool AllowCustomBaseUrlValue;
        internal TimeSpan TimeoutValue = TimeSpan.FromSeconds(30);
        internal int MaxNetworkRetriesValue = 2;
        internal IReadOnlyList<string>? UploadHostsValue;
        internal string ChannelValue = "";
        internal string FunnelValue = "";
        internal string UploadRootValue = "";
        internal string CaBundleValue = "";

        public Builder WorkspaceId(string? value) { WorkspaceValue = value; return this; }
        public Builder Env(string? value) { EnvValue = value; return this; }
        public Builder BaseUrl(string? value) { BaseUrlValue = value; return this; }
        public Builder AllowCustomBaseUrl(bool value) { AllowCustomBaseUrlValue = value; return this; }
        public Builder Timeout(TimeSpan value) { TimeoutValue = value; return this; }
        public Builder MaxNetworkRetries(int value) { MaxNetworkRetriesValue = value; return this; }
        public Builder UploadHosts(IReadOnlyList<string>? value) { UploadHostsValue = value; return this; }
        public Builder Channel(string? value) { ChannelValue = value ?? ""; return this; }
        public Builder Funnel(string? value) { FunnelValue = value ?? ""; return this; }
        public Builder UploadRoot(string? value) { UploadRootValue = value ?? ""; return this; }
        public Builder CaBundle(string? value) { CaBundleValue = value ?? ""; return this; }

        public ClientOptions Build() => new(this);
    }
}
