using System.Collections.Concurrent;
using System.Net;

namespace Nwtoolkit;

/// <summary>
/// Reverse DNS with a process-wide cache. A hop or peer is looked up once; every later
/// display of the same address is instant. A lookup that takes too long is given up on
/// for now, but the answer is still stored when it arrives, so a slow resolver only
/// delays the name rather than costing the wait on every round.
/// </summary>
public static class ReverseDns
{
    static readonly ConcurrentDictionary<string, string> cache = new();
    static readonly TimeSpan wait = TimeSpan.FromSeconds(2);

    /// <summary>The host name for the address, or "" when there is none (also cached).</summary>
    public static string Name(IPAddress ip)
    {
        var key = ip.ToString();
        if (cache.TryGetValue(key, out var known)) return known;

        var name = "";
        try
        {
            var task = Dns.GetHostEntryAsync(ip);
            if (task.Wait(wait))
            {
                name = Clean(task.Result.HostName, key);
            }
            else
            {
                // keep the entry empty for now; fill it in when the resolver answers
                _ = task.ContinueWith(t =>
                {
                    if (t.IsCompletedSuccessfully) cache[key] = Clean(t.Result.HostName, key);
                }, TaskScheduler.Default);
            }
        }
        catch
        {
            // no PTR record, or the resolver refused: cache the miss so it is not retried every second
        }
        cache[key] = name;
        return name;
    }

    /// <summary>"name (ip)" when a name is known, otherwise just the address.</summary>
    public static string Label(IPAddress ip)
    {
        var name = Name(ip);
        return name == "" ? ip.ToString() : $"{name} ({ip})";
    }

    static string Clean(string host, string ipText)
    {
        if (string.IsNullOrEmpty(host) || host == ipText) return "";
        return host.TrimEnd('.');
    }
}
