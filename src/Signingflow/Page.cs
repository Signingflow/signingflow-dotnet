using System.Runtime.CompilerServices;

namespace Signingflow;

public sealed class Page<T>
{
    internal const int MaxPages = 100;
    private readonly Loader? _load;

    internal Page(IReadOnlyList<T> data, string? nextPageToken, Loader? load)
    {
        Data = data.ToArray();
        NextPageToken = nextPageToken ?? "";
        _load = load;
    }

    public IReadOnlyList<T> Data { get; }
    public string NextPageToken { get; }

    public async IAsyncEnumerable<T> AllAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        Page<T> page = this;
        int index = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int pages = 0;
        while (true)
        {
            while (index < page.Data.Count)
            {
                yield return page.Data[index++];
            }
            string token = page.NextPageToken;
            if (token.Length == 0 || page._load == null)
            {
                yield break;
            }
            if (!seen.Add(token))
            {
                yield break;
            }
            pages++;
            if (pages > MaxPages)
            {
                throw new TooManyPagesException();
            }
            Page<T> next;
            try
            {
                next = await page._load(token, cancellationToken).ConfigureAwait(false);
            }
            catch (SigningflowException ex)
            {
                throw new LoadException(ex);
            }
            page = new Page<T>(next.Data, next.NextPageToken, page._load);
            index = 0;
        }
    }

    internal static string NextToken(object? body)
    {
        Dictionary<string, object?>? map = Json.AsMap(body);
        if (map == null)
        {
            return "";
        }
        string token = Json.AsString(map.GetValueOrDefault("next_page_token"));
        return token.Length > 0 ? token : Json.AsString(map.GetValueOrDefault("nextPageToken"));
    }

    internal static List<object?> Items(object? body, string key)
    {
        Dictionary<string, object?>? map = Json.AsMap(body);
        if (map != null && map.GetValueOrDefault(key) is List<object?> list)
        {
            return list;
        }
        return [];
    }

    internal static int PageSize(int? value)
    {
        if (value == null)
        {
            return 10;
        }
        if (value < 1 || value > 1000)
        {
            throw new SigningflowException.InvalidRequestException("page_size must be from 1 to 1000.");
        }
        return value.Value;
    }

    internal delegate Task<Page<T>> Loader(string token, CancellationToken cancellationToken);

    public sealed class TooManyPagesException : Exception
    {
        public TooManyPagesException()
            : base("Too many pages.")
        {
        }
    }

    public sealed class LoadException : Exception
    {
        public LoadException(SigningflowException cause)
            : base(cause.Message, cause)
        {
        }
    }
}
