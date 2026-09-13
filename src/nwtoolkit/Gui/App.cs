using System.IO;
using System.Windows;

namespace Nwtoolkit.Gui;

/// <summary>Starts the WPF window with the Fluent theme following the Windows light/dark app mode.</summary>
public static class App
{
    /// <summary>Shows the native window. Called for a double-click and for `nwtoolkit gui`.</summary>
    public static void RunGui()
    {
        Term.DetachConsole(); // hide the console when double-clicked
        Util.UseColor = false;
        try
        {
            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            app.ThemeMode = ThemeMode.System; // Fluent theme; light or dark as Windows says
            app.DispatcherUnhandledException += (_, e) =>
            {
                CrashLog(e.Exception);
                e.Handled = true;
            };
            app.Run(new MainWindow());
        }
        catch (Exception e)
        {
            CrashLog(e);
        }
    }

    /// <summary>Writes text to nwtoolkit-crash.log next to the exe, or in TEMP, and returns the path it used.</summary>
    static string WriteCrash(string msg)
    {
        var dir = ".";
        try
        {
            if (Environment.ProcessPath is { } exe) dir = Path.GetDirectoryName(exe) ?? ".";
        }
        catch { }
        var path = Path.Combine(dir, "nwtoolkit-crash.log");
        try
        {
            File.WriteAllText(path, msg);
        }
        catch
        {
            path = Path.Combine(Path.GetTempPath(), "nwtoolkit-crash.log");
            try { File.WriteAllText(path, msg); } catch { }
        }
        return path;
    }

    /// <summary>Logs an unhandled exception with its stack trace and shows an error message.</summary>
    public static void CrashLog(Exception e)
    {
        var msg = $"nwtoolkit {Util.Version} crash {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n{e}\n";
        var path = WriteCrash(msg);
        MessageBox.Show($"{e.Message}\n\nDetails saved to:\n{path}", "nwtoolkit - error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
