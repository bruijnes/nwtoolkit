using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;

namespace Nwtoolkit;

/// <summary>Administrator rights: detection and the UAC-driven relaunch.</summary>
public static class Elevation
{
    /// <summary>
    /// Whether the process runs with elevated rights. Only meaningful on Windows, which
    /// has UAC; elsewhere there is no prompt-driven elevation, so report elevated and let
    /// the raw-socket calls surface a permission error themselves.
    /// </summary>
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return true;
        return IsElevatedWindows();
    }

    [SupportedOSPlatform("windows")]
    static bool IsElevatedWindows()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Starts a fresh copy of this executable with the given arguments through the
    /// "runas" verb, which raises the standard Windows UAC prompt. This is the supported
    /// way to elevate: it asks the user for consent, it does not bypass anything. On
    /// success the caller should exit, leaving the elevated copy running. If the user
    /// dismisses the UAC prompt an exception is thrown and nothing changes.
    /// </summary>
    public static void RelaunchAsAdmin(IEnumerable<string> args)
    {
        if (!OperatingSystem.IsWindows()) throw new Exception("restarting as administrator is only supported on Windows");
        var exe = Environment.ProcessPath ?? throw new Exception("cannot determine the executable path");
        var psi = new ProcessStartInfo(exe)
        {
            Arguments = CommandLine(args),
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Environment.CurrentDirectory,
        };
        try
        {
            Process.Start(psi);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            throw new Exception("the elevation prompt was dismissed");
        }
        catch (Win32Exception e)
        {
            throw new Exception($"ShellExecute failed: {e.Message}");
        }
    }

    /// <summary>Quotes arguments that contain spaces or quotes so the relaunched process receives them intact.</summary>
    public static string CommandLine(IEnumerable<string> args)
    {
        var b = new StringBuilder();
        var first = true;
        foreach (var a in args)
        {
            if (!first) b.Append(' ');
            first = false;
            if (a == "" || a.IndexOfAny(new[] { ' ', '\t', '"' }) >= 0)
                b.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
            else
                b.Append(a);
        }
        return b.ToString();
    }
}
