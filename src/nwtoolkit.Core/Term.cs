using System.Runtime.InteropServices;

namespace Nwtoolkit;

/// <summary>Console plumbing that differs per platform: ANSI colours, console detection.</summary>
public static class Term
{
    const int StdOutputHandle = -11;
    const uint EnableVirtualTerminalProcessing = 0x0004;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetConsoleProcessList([Out] uint[] processList, uint processCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeConsole();

    /// <summary>Switches the console to ANSI escape processing. Returns whether colours can be used.</summary>
    public static bool EnableVT()
    {
        if (!OperatingSystem.IsWindows())
            return !Console.IsOutputRedirected;
        try
        {
            var h = GetStdHandle(StdOutputHandle);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) return false;
            if (!GetConsoleMode(h, out var mode)) return false;
            return SetConsoleMode(h, mode | EnableVirtualTerminalProcessing);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Decides whether the exe was double-clicked, giving it its own console with one
    /// process, versus started from an existing terminal, where two or more processes
    /// share the console.
    /// </summary>
    public static bool LaunchedFromExplorer()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            var ids = new uint[4];
            return GetConsoleProcessList(ids, (uint)ids.Length) == 1;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Detaches from the console, so the window disappears when the GUI starts.</summary>
    public static void DetachConsole()
    {
        if (!OperatingSystem.IsWindows()) return;
        try { FreeConsole(); } catch { }
    }
}
