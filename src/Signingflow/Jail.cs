using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Signingflow;

public static partial class Jail
{
    public const int MaxBytes = 25 * 1024 * 1024;
    private const int SIfmt = 0xF000;
    private const int SIfreg = 0x8000;

    public static byte[] Read(string? uploadRoot, string? requested) => Read(uploadRoot, requested, MaxBytes);

    public static byte[] Read(string? uploadRoot, string? requested, int maxBytes)
    {
        if (string.IsNullOrWhiteSpace(uploadRoot))
        {
            throw new SigningflowException.InvalidRequestException("A filesystem path requires upload_root.");
        }
        try
        {
            return ReadJailed(uploadRoot, requested ?? "", maxBytes);
        }
        catch (SigningflowException.InvalidRequestException)
        {
            throw;
        }
        catch (IOException)
        {
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
    }

    private static byte[] ReadJailed(string rootText, string requested, int maxBytes)
    {
        if (requested.Length == 0 || requested.Contains('\0'))
        {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        if (Path.IsPathRooted(requested))
        {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        foreach (string segment in requested.Split('/'))
        {
            if (segment == "..")
            {
                throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
            }
        }
        if (OperatingSystem.IsWindows())
        {
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
        string root = Real(rootText);
        string resolved = Path.GetFullPath(Path.Combine(root, requested));
        if (!Within(root, resolved) || resolved == root)
        {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        string? parent = Path.GetDirectoryName(resolved);
        if (string.IsNullOrEmpty(parent))
        {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        string parentReal = Real(parent);
        if (!Within(root, parentReal))
        {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        string leaf = Path.Combine(parentReal, Path.GetFileName(resolved));
        if (!Within(root, leaf) || leaf == root)
        {
            throw new SigningflowException.InvalidRequestException("The path is outside upload_root.");
        }
        byte[] stat = Status(leaf);
        (int mode, ulong links, long size) = Identity(stat);
        if ((mode & SIfmt) != SIfreg)
        {
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
        if (links > 1)
        {
            throw new SigningflowException.InvalidRequestException("The file must not be a hard link.");
        }
        if (links < 1)
        {
            throw new SigningflowException.InvalidRequestException("The file could not be read.");
        }
        if (size > maxBytes)
        {
            throw new SigningflowException.InvalidRequestException("The file is larger than 25 MB.");
        }
        if (size == 0)
        {
            return [];
        }
        int flags = OpenReadFlags();
        int fd = Open(leaf, flags, 0);
        if (fd < 0)
        {
            throw new IOException("open failed");
        }
        try
        {
            byte[] opened = StatusFd(fd);
            if (Identity(opened).Size != size)
            {
                throw new SigningflowException.InvalidRequestException("The file could not be read.");
            }
            var buffer = new byte[size];
            int filled = 0;
            while (filled < buffer.Length)
            {
                int read = ReadRaw(fd, ref buffer[filled], (nuint)(buffer.Length - filled));
                if (read < 0)
                {
                    throw new IOException("read failed");
                }
                if (read == 0)
                {
                    throw new SigningflowException.InvalidRequestException("The file could not be read.");
                }
                filled += read;
            }
            return buffer;
        }
        finally
        {
            _ = Close(fd);
        }
    }

    private static bool Within(string root, string path) =>
        path.Equals(root, StringComparison.Ordinal) ||
        path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal);

    private static string Real(string path)
    {
        var buffer = new byte[4096];
        IntPtr result = RealPath(path, buffer);
        if (result == IntPtr.Zero)
        {
            throw new IOException("realpath failed");
        }
        int length = Array.IndexOf(buffer, (byte)0);
        if (length < 0)
        {
            length = buffer.Length;
        }
        return Encoding.UTF8.GetString(buffer, 0, length);
    }

    private static byte[] Status(string path)
    {
        var buffer = new byte[256];
        if (LStat(path, buffer) != 0)
        {
            throw new IOException("lstat failed");
        }
        return buffer;
    }

    private static byte[] StatusFd(int fd)
    {
        var buffer = new byte[256];
        if (FStat(fd, buffer) != 0)
        {
            throw new IOException("fstat failed");
        }
        return buffer;
    }

    private static (int Mode, ulong Links, long Size) Identity(byte[] buffer) =>
        DecodeStat(buffer, OperatingSystem.IsMacOS(), OperatingSystem.IsLinux(), RuntimeInformation.ProcessArchitecture);

    internal static (int Mode, ulong Links, long Size) DecodeStat(byte[] buffer, bool macOs, bool linux, Architecture architecture)
    {
        if (macOs)
        {
            int mode = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(4));
            ulong links = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(6));
            long size = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(96));
            return (mode, links, size);
        }
        if (linux && architecture == Architecture.Arm64)
        {
            int mode = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(16));
            ulong links = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(20));
            long size = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(40));
            return (mode, links, size);
        }
        if (linux && architecture == Architecture.X64)
        {
            ulong links = BinaryPrimitives.ReadUInt64LittleEndian(buffer.AsSpan(16));
            int mode = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(24));
            long size = BinaryPrimitives.ReadInt64LittleEndian(buffer.AsSpan(48));
            return (mode, links, size);
        }
        throw new IOException("stat layout is not supported");
    }

    private static int OpenReadFlags()
    {
        int noFollow = OperatingSystem.IsLinux() ? 0x20000 : 0x100;
        int cloexec = OperatingSystem.IsLinux() ? 0x80000 : 0x1000000;
        return noFollow | cloexec;
    }

    [LibraryImport("libc", EntryPoint = "lstat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int LStat(string path, byte[] buffer);

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int fd, byte[] buffer);

    [LibraryImport("libc", EntryPoint = "realpath", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr RealPath(string path, byte[] buffer);

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags, int mode);

    [LibraryImport("libc", EntryPoint = "read", SetLastError = true)]
    private static partial int ReadRaw(int fd, ref byte buffer, nuint count);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int fd);
}
