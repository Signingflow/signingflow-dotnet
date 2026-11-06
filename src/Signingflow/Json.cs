using System.Globalization;
using System.Text;

namespace Signingflow;

/// <summary>A small JSON reader and writer for the allowlist payloads.</summary>
public static class Json
{
    private const int MaxDepth = 32;

    public static string Write(object? value)
    {
        var output = new StringBuilder();
        WriteValue(value, output, 0);
        return output.ToString();
    }

    public static object? Read(string? text)
    {
        if (text == null)
        {
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }
        var parser = new Parser(text);
        object? value = parser.Parse(0);
        parser.SkipWs();
        if (!parser.Done())
        {
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }
        return value;
    }

    public static Dictionary<string, object?>? AsMap(object? value) => value as Dictionary<string, object?>;

    public static string AsString(object? value) => value as string ?? "";

    public static int? AsInt(object? value)
    {
        switch (value)
        {
            case bool:
                return null;
            case long number:
                return number < int.MinValue || number > int.MaxValue ? null : (int)number;
            case int number:
                return number;
            case double number:
                return (int)number;
            case string text:
                return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) ? parsed : null;
            default:
                return null;
        }
    }

    private static void WriteValue(object? value, StringBuilder output, int depth)
    {
        if (depth > MaxDepth)
        {
            throw new SigningflowException.InvalidRequestException("invalid request body");
        }
        if (value == null)
        {
            output.Append("null");
            return;
        }
        if (value is string text)
        {
            WriteString(text, output);
            return;
        }
        if (value is bool boolean)
        {
            output.Append(boolean ? "true" : "false");
            return;
        }
        if (value is byte or sbyte or short or ushort or int or uint or long)
        {
            output.Append(Convert.ToInt64(value, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));
            return;
        }
        if (value is float or double)
        {
            double number = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            if (double.IsNaN(number) || double.IsInfinity(number))
            {
                throw new SigningflowException.InvalidRequestException("invalid request body");
            }
            output.Append(number.ToString("R", CultureInfo.InvariantCulture));
            return;
        }
        if (value is System.Collections.IDictionary map)
        {
            output.Append('{');
            bool first = true;
            foreach (System.Collections.DictionaryEntry entry in map)
            {
                if (entry.Key is not string key)
                {
                    throw new SigningflowException.InvalidRequestException("invalid request body");
                }
                if (!first)
                {
                    output.Append(',');
                }
                first = false;
                WriteString(key, output);
                output.Append(':');
                WriteValue(entry.Value, output, depth + 1);
            }
            output.Append('}');
            return;
        }
        if (value is System.Collections.IEnumerable items)
        {
            output.Append('[');
            bool first = true;
            foreach (object? item in items)
            {
                if (!first)
                {
                    output.Append(',');
                }
                first = false;
                WriteValue(item, output, depth + 1);
            }
            output.Append(']');
            return;
        }
        throw new SigningflowException.InvalidRequestException("invalid request body");
    }

    private static void WriteString(string text, StringBuilder output)
    {
        output.Append('"');
        foreach (char c in text)
        {
            switch (c)
            {
                case '"':
                    output.Append("\\\"");
                    break;
                case '\\':
                    output.Append("\\\\");
                    break;
                case '\b':
                    output.Append("\\b");
                    break;
                case '\f':
                    output.Append("\\f");
                    break;
                case '\n':
                    output.Append("\\n");
                    break;
                case '\r':
                    output.Append("\\r");
                    break;
                case '\t':
                    output.Append("\\t");
                    break;
                default:
                    if (c < 0x20)
                    {
                        output.Append("\\u");
                        output.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        output.Append(c);
                    }
                    break;
            }
        }
        output.Append('"');
    }

    private sealed class Parser
    {
        private readonly string _text;
        private int _index;

        internal Parser(string text) => _text = text;

        internal object? Parse(int depth)
        {
            if (depth > MaxDepth)
            {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            SkipWs();
            if (Done())
            {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            char c = _text[_index];
            if (c == '{')
            {
                return ParseObject(depth);
            }
            if (c == '[')
            {
                return ParseArray(depth);
            }
            if (c == '"')
            {
                return ParseString();
            }
            if (c == 't' || c == 'f')
            {
                return ParseBoolean();
            }
            if (c == 'n')
            {
                return ParseNull();
            }
            if (c == '-' || (c >= '0' && c <= '9'))
            {
                return ParseNumber();
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private Dictionary<string, object?> ParseObject(int depth)
        {
            Expect('{');
            var map = new Dictionary<string, object?>();
            SkipWs();
            if (Peek('}'))
            {
                _index++;
                return map;
            }
            while (true)
            {
                SkipWs();
                if (Done() || _text[_index] != '"')
                {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                string key = ParseString();
                SkipWs();
                Expect(':');
                map[key] = Parse(depth + 1);
                SkipWs();
                if (Peek('}'))
                {
                    _index++;
                    return map;
                }
                Expect(',');
            }
        }

        private List<object?> ParseArray(int depth)
        {
            Expect('[');
            var list = new List<object?>();
            SkipWs();
            if (Peek(']'))
            {
                _index++;
                return list;
            }
            while (true)
            {
                list.Add(Parse(depth + 1));
                SkipWs();
                if (Peek(']'))
                {
                    _index++;
                    return list;
                }
                Expect(',');
            }
        }

        private string ParseString()
        {
            Expect('"');
            var output = new StringBuilder();
            while (!Done())
            {
                char c = _text[_index++];
                if (c == '"')
                {
                    return output.ToString();
                }
                if (c == '\\')
                {
                    if (Done())
                    {
                        break;
                    }
                    char escaped = _text[_index++];
                    switch (escaped)
                    {
                        case '"':
                        case '\\':
                        case '/':
                            output.Append(escaped);
                            break;
                        case 'b':
                            output.Append('\b');
                            break;
                        case 'f':
                            output.Append('\f');
                            break;
                        case 'n':
                            output.Append('\n');
                            break;
                        case 'r':
                            output.Append('\r');
                            break;
                        case 't':
                            output.Append('\t');
                            break;
                        case 'u':
                            output.Append(ParseHex());
                            break;
                        default:
                            throw new SigningflowException.ApiException("The API returned invalid JSON.");
                    }
                    continue;
                }
                if (c < 0x20)
                {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                output.Append(c);
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private char ParseHex()
        {
            if (_index + 4 > _text.Length)
            {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            int code = 0;
            for (int i = 0; i < 4; i++)
            {
                int digit = Hex.FromHex(_text[_index++]);
                if (digit < 0)
                {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                code = (code << 4) + digit;
            }
            return (char)code;
        }

        private bool ParseBoolean()
        {
            if (_text.AsSpan(_index).StartsWith("true"))
            {
                _index += 4;
                return true;
            }
            if (_text.AsSpan(_index).StartsWith("false"))
            {
                _index += 5;
                return false;
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private object? ParseNull()
        {
            if (_text.AsSpan(_index).StartsWith("null"))
            {
                _index += 4;
                return null;
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private object ParseNumber()
        {
            int start = _index;
            if (Peek('-'))
            {
                _index++;
            }
            if (Done() || !Digit())
            {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            if (_text[_index] == '0')
            {
                _index++;
            }
            else
            {
                while (!Done() && Digit())
                {
                    _index++;
                }
            }
            bool fractional = false;
            if (!Done() && _text[_index] == '.')
            {
                fractional = true;
                _index++;
                if (Done() || !Digit())
                {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                while (!Done() && Digit())
                {
                    _index++;
                }
            }
            if (!Done() && (_text[_index] == 'e' || _text[_index] == 'E'))
            {
                fractional = true;
                _index++;
                if (!Done() && (_text[_index] == '+' || _text[_index] == '-'))
                {
                    _index++;
                }
                if (Done() || !Digit())
                {
                    throw new SigningflowException.ApiException("The API returned invalid JSON.");
                }
                while (!Done() && Digit())
                {
                    _index++;
                }
            }
            string token = _text[start.._index];
            if (!fractional)
            {
                if (long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out long whole))
                {
                    return whole;
                }
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            if (double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out double real))
            {
                return real;
            }
            throw new SigningflowException.ApiException("The API returned invalid JSON.");
        }

        private bool Digit()
        {
            char c = _text[_index];
            return c >= '0' && c <= '9';
        }

        private void Expect(char c)
        {
            if (Done() || _text[_index] != c)
            {
                throw new SigningflowException.ApiException("The API returned invalid JSON.");
            }
            _index++;
        }

        private bool Peek(char c) => !Done() && _text[_index] == c;

        internal void SkipWs()
        {
            while (!Done())
            {
                char c = _text[_index];
                if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
                {
                    return;
                }
                _index++;
            }
        }

        internal bool Done() => _index >= _text.Length;
    }
}

internal static class Hex
{
    public static int FromHex(char value) => Uri.IsHexDigit(value) ? Convert.ToInt32(value.ToString(), 16) : -1;
}
