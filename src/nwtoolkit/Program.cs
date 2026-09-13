using Nwtoolkit.Gui;

namespace Nwtoolkit;

static class Program
{
    [STAThread]
    static int Main(string[] args) => Cli.Run(args, App.RunGui);
}
