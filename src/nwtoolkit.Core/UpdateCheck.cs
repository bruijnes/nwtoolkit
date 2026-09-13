using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Nwtoolkit;

/// <summary>A newer release on GitHub, if there is one.</summary>
public sealed record UpdateInfo(string Latest, string Url);

/// <summary>
/// Asks the GitHub releases API for the newest release and compares it with the running
/// version. Any failure (offline, rate-limited, no releases yet) simply means "no update
/// known"; the check never gets in the way of the tool.
/// </summary>
public static class UpdateCheck
{
    public const string Repo = "bruijnes/nwtoolkit";
    public const string DownloadPage = "https://github.com/" + Repo + "/releases/latest";
    const string ApiLatest = "https://api.github.com/repos/" + Repo + "/releases/latest";

    /// <summary>Returns the newer release, or null when up to date or unknown.</summary>
    public static async Task<UpdateInfo?> Latest(TimeSpan timeout, CancellationToken ct = default)
    {
        try
        {
            using var http = new HttpClient { Timeout = timeout };
            http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("nwtoolkit", Util.Version));
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            using var resp = await http.GetAsync(ApiLatest, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null;
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            var root = doc.RootElement;
            var tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
            var url = root.TryGetProperty("html_url", out var u) ? u.GetString() ?? DownloadPage : DownloadPage;
            var latest = Normalize(tag);
            return IsNewer(latest, Util.Version) ? new UpdateInfo(latest, url) : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>"v1.29" → "1.29".</summary>
    public static string Normalize(string tag)
    {
        tag = tag.Trim();
        if (tag.StartsWith('v') || tag.StartsWith('V')) tag = tag[1..];
        return tag;
    }

    /// <summary>Whether <paramref name="candidate"/> is a higher version than <paramref name="current"/>.</summary>
    public static bool IsNewer(string candidate, string current)
    {
        if (!Version.TryParse(Pad(Normalize(candidate)), out var a)) return false;
        if (!Version.TryParse(Pad(Normalize(current)), out var b)) return false;
        return a > b;
    }

    // Version.TryParse needs at least two components
    static string Pad(string v) => v.Contains('.') ? v : v + ".0";
}
