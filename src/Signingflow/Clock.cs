namespace Signingflow;

/// <summary>Time source. Tests replace <see cref="Now"/> and <see cref="Delay"/>.</summary>
public static class Clock
{
    private static readonly Func<TimeSpan, CancellationToken, Task> Sleep = (duration, cancellationToken) =>
    {
        if (duration <= TimeSpan.Zero)
        {
            return Task.CompletedTask;
        }
        return Task.Delay(duration, cancellationToken);
    };

    public static Func<DateTimeOffset> Now = () => DateTimeOffset.UtcNow;
    public static Func<TimeSpan, CancellationToken, Task> Delay = Sleep;

    public static DateTimeOffset Instant() => Now();

    public static Task PauseAsync(TimeSpan duration, CancellationToken cancellationToken = default) =>
        Delay(duration, cancellationToken);

    public static void Reset()
    {
        Now = () => DateTimeOffset.UtcNow;
        Delay = Sleep;
    }
}
