using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Navigation;
using static Nwtoolkit.Util;

namespace Nwtoolkit.Gui;

/// <summary>A cancellable background task per tab; starting again stops the previous run.</summary>
sealed class Job
{
    CancellationTokenSource? cts;

    public CancellationToken Start()
    {
        Halt();
        cts = new CancellationTokenSource();
        return cts.Token;
    }

    public void Halt()
    {
        var old = cts;
        cts = null;
        if (old == null) return;
        try { old.Cancel(); } catch (ObjectDisposedException) { }
    }
}

/// <summary>The native window: one tab per feature, with a live chart where it makes sense.</summary>
public partial class MainWindow : Window
{
    readonly ChartData pData = new("ms"), dsData = new("ms"), dhData = new("ms");
    readonly Job pJob = new(), dsJob = new(), dhJob = new(), trJob = new(), llJob = new();

    const string MitLicense = "MIT License\r\n\r\n" +
        "Copyright (c) 2026 Vincent Bruijnes\r\n\r\n" +
        "Permission is hereby granted, free of charge, to any person obtaining a copy\r\n" +
        "of this software and associated documentation files (the \"Software\"), to deal\r\n" +
        "in the Software without restriction, including without limitation the rights\r\n" +
        "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\r\n" +
        "copies of the Software, and to permit persons to whom the Software is\r\n" +
        "furnished to do so, subject to the following conditions:\r\n\r\n" +
        "The above copyright notice and this permission notice shall be included in all\r\n" +
        "copies or substantial portions of the Software.\r\n\r\n" +
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\r\n" +
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\r\n" +
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\r\n" +
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\r\n" +
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\r\n" +
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\r\n" +
        "SOFTWARE.";

    public MainWindow()
    {
        InitializeComponent();
        Title = $"nwtoolkit {Util.Version} — network diagnostics";
        AboutTitle.Text = "nwtoolkit " + Util.Version;
        AboutLic.Text = MitLicense;
        AboutLink.NavigateUri = new Uri("https://github.com/bruijnes/");
        LoadIcon();
        PChart.Data = pData;
        DsChart.Data = dsData;
        DhChart.Data = dhData;

        Loaded += (_, _) =>
        {
            ApplyTheme();
            PopulateInterfaces();
            CheckForUpdate();
        };
        Closing += (_, _) =>
        {
            pJob.Halt();
            dsJob.Halt();
            dhJob.Halt();
            trJob.Halt();
            llJob.Halt();
        };
    }

    /// <summary>The window icon from the embedded .ico; a failure here must never stop the window.</summary>
    void LoadIcon()
    {
        try
        {
            var info = Application.GetResourceStream(new Uri("pack://application:,,,/nwtoolkit.ico"));
            if (info?.Stream is { } s)
            {
                using (s) Icon = System.Windows.Media.Imaging.BitmapFrame.Create(s, System.Windows.Media.Imaging.BitmapCreateOptions.None, System.Windows.Media.Imaging.BitmapCacheOption.OnLoad);
            }
        }
        catch { }
    }

    /// <summary>The output boxes share the chart's plot colour, so every text area looks the same.</summary>
    void ApplyTheme()
    {
        var dark = Theme.IsDark(this);
        var bg = ChartControl.PlotBackground(this);
        // white text on the grey boxes in dark mode; the theme's normal text colour otherwise
        var fg = dark ? new SolidColorBrush(Color.FromRgb(0xf4, 0xf4, 0xf4))
                      : TryFindResource("TextFillColorPrimaryBrush") as Brush ?? Brushes.Black;
        foreach (var tb in new[] { PLog, TrOut, DOut, DhOut, LlOut, AboutLic })
        {
            tb.Background = bg;
            tb.Foreground = fg;
            tb.CaretBrush = fg;
        }
        foreach (var cb in new[] { PResolve, TrMon, TrResolve }) cb.Foreground = fg;
        AboutText.Foreground = fg;
        AboutBox.Background = bg;
        AboutBox.BorderBrush = TryFindResource("ControlStrokeColorDefaultBrush") as Brush ?? Brushes.Gray;
        UpdateBar.Background = TryFindResource("SystemFillColorAttentionBackgroundBrush") as Brush
                               ?? new SolidColorBrush(Theme.IsDark(this) ? Color.FromRgb(0x2b, 0x3d, 0x52) : Color.FromRgb(0xe6, 0xf0, 0xfb));
        UpdateBar.BorderBrush = TryFindResource("ControlStrokeColorDefaultBrush") as Brush ?? Brushes.Gray;
    }

    /// <summary>Looks for a newer GitHub release in the background and shows the bar when there is one.</summary>
    void CheckForUpdate()
    {
        Task.Run(async () =>
        {
            var upd = await UpdateCheck.Latest(TimeSpan.FromSeconds(8));
            if (upd == null) return;
            Sync(() =>
            {
                UpdateText.Text = $"A newer version is available: {upd.Latest} (you have {Util.Version}). ";
                UpdateLink.NavigateUri = new Uri(upd.Url);
                UpdateBar.Visibility = Visibility.Visible;
            });
        });
    }

    void PopulateInterfaces()
    {
        // DHCP interface list from the real NICs
        DhIf.Items.Clear();
        DhIf.Items.Add("(automatic)");
        foreach (var ic in Dhcp.UsableIPv4Ifaces()) DhIf.Items.Add($"{ic.Name}  ({ic.Ip})");
        DhIf.SelectedIndex = 0;

        Task.Run(() =>
        {
            var (_, devs, _) = Lldp.Open("");
            if (devs.Count > 0) Sync(() => { foreach (var d in devs) LlIf.Items.Add(d); });
        });
    }

    // ---- helpers ----

    void Sync(Action f)
    {
        try { Dispatcher.BeginInvoke(f); } catch (Exception) { }
    }

    void SetStatus(string s) => Status.Text = s;

    bool UseV6 => IpVer.SelectedIndex == 1;

    static double Atof(string s, double def) =>
        double.TryParse(s.Trim().Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : def;

    static void Append(TextBox box, string text)
    {
        box.AppendText(text);
        box.ScrollToEnd();
    }

    void OpenLink(object sender, RequestNavigateEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true }); }
        catch { }
        e.Handled = true;
    }

    /// <summary>
    /// Returns true when the process already runs as administrator. Otherwise it offers,
    /// through a UAC prompt, to restart nwtoolkit elevated; on consent it launches the
    /// elevated copy and exits this one. Returns false when the user declines or the
    /// relaunch fails, so the caller can abort the action.
    /// </summary>
    bool EnsureElevated(string reason)
    {
        if (Elevation.IsElevated()) return true;
        if (MessageBox.Show(this, reason + "\n\nRestart nwtoolkit as administrator?", "Administrator required",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return false;
        try
        {
            Elevation.RelaunchAsAdmin(new[] { "gui" });
        }
        catch (Exception e)
        {
            MessageBox.Show(this, "Restarting as administrator failed:\n" + e.Message, "Could not restart", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
        Environment.Exit(0);
        return false;
    }

    /// <summary>Runs a measurement every interval on a background thread and feeds the chart, stats line and log.</summary>
    void StartSpeed(Job j, ChartData cd, ChartControl chart, TextBlock stats, TextBox? log, string name, TimeSpan interval,
        Func<(double Value, string Info, string? Error)> measure)
    {
        var token = j.Start();
        cd.Reset();
        chart.InvalidateVisual();
        SetStatus(name + " running…");
        if (interval <= TimeSpan.Zero) interval = TimeSpan.FromSeconds(1);
        Task.Run(() =>
        {
            while (true)
            {
                var (v, info, err) = measure();
                if (token.IsCancellationRequested) break;
                cd.Push(v, err == null);
                var (vals, _, lost, n) = cd.Snapshot();
                var txt = ChartData.StatsText(vals, lost, n, cd.Unit);
                Sync(() =>
                {
                    stats.Text = txt;
                    SetStatus(name + " running — " + txt);
                    chart.InvalidateVisual();
                    if (log != null)
                    {
                        var ts = DateTime.Now.ToString("HH:mm:ss");
                        Append(log, err != null ? $"{ts}  error: {err}\r\n" : $"{ts}  {v.F(2)} {cd.Unit}   {info}\r\n");
                    }
                });
                if (token.WaitHandle.WaitOne(interval)) break;
            }
            Sync(() => SetStatus(name + " stopped."));
        });
    }

    // ---- ping ----

    void StartPing(object sender, RoutedEventArgs e)
    {
        IPAddress ip;
        try { ip = ResolveIP(PHost.Text, UseV6); }
        catch (Exception ex)
        {
            SetStatus("error: " + ex.Message);
            return;
        }
        var echo = new Echo();
        var payload = Encoding.ASCII.GetBytes("nwtoolkit");
        var resolve = PResolve.IsChecked == true;
        StartSpeed(pJob, pData, PChart, PStats, PLog, "Ping", Dur(Atof(PInt.Text, 1)), () =>
        {
            var r = echo.Send(ip, 128, TimeSpan.FromSeconds(2), payload);
            if (r.Error != null) return (0, "", r.Error);
            if (r.Status != System.Net.NetworkInformation.IPStatus.Success) return (0, "", Echo.StatusText(r.Status));
            var from = r.Peer == null ? "?" : resolve ? ReverseDns.Label(r.Peer) : r.Peer.ToString();
            return (r.Ms, "from " + from, null);
        });
    }

    void StopPing(object sender, RoutedEventArgs e) => pJob.Halt();

    // ---- traceroute ----

    void StartTrace(object sender, RoutedEventArgs e)
    {
        IPAddress dst;
        try { dst = ResolveIP(TrHost.Text, UseV6); }
        catch (Exception ex)
        {
            TrOut.Text = "error: " + ex.Message;
            return;
        }
        var host = TrHost.Text;
        var mon = TrMon.IsChecked == true;
        var resolve = TrResolve.IsChecked == true;
        var token = trJob.Start();
        SetStatus("Traceroute running…");
        Task.Run(() =>
        {
            using var echo = new Echo();
            while (true)
            {
                var hops = Traceroute.RunTrace(echo, dst, new TraceOpts { MaxHops = 30, Probes = 3, Timeout = TimeSpan.FromSeconds(2), Resolve = resolve }, token);
                if (token.IsCancellationRequested) return;
                var txt = Traceroute.TraceText(host, dst.ToString(), hops);
                Sync(() =>
                {
                    TrOut.Text = txt;
                    SetStatus("Traceroute done.");
                });
                if (!mon) return;
                if (token.WaitHandle.WaitOne(TimeSpan.FromSeconds(3))) return;
            }
        });
    }

    void StopTrace(object sender, RoutedEventArgs e) => trJob.Halt();

    // ---- dns ----

    void RunDnsQuery(object sender, RoutedEventArgs e)
    {
        IPEndPoint server;
        try { server = DnsCmd.ServerAddr(DServer.Text, UseV6); }
        catch (Exception ex)
        {
            DOut.Text = "error: " + ex.Message;
            return;
        }
        var qt = DnsWire.TypeCode((DType.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "A");
        var name = DName.Text.Trim();
        DOut.Text = "working…";
        SetStatus("DNS query…");
        Task.Run(() =>
        {
            var sb = new StringBuilder();
            try
            {
                var (rtt, ans) = DnsWire.Query(server, name, qt, TimeSpan.FromSeconds(3));
                sb.Append($"Server:        {server}\r\nResponse time: {Ms(rtt).F(2)} ms\r\n\r\n");
                if (ans.Count == 0) sb.Append("(no records)\r\n");
                foreach (var a in ans) sb.Append(a).Append("\r\n");
            }
            catch (DnsRcodeException ex)
            {
                sb.Append($"Server:        {server}\r\nResponse time: {Ms(ex.Rtt).F(2)} ms\r\n\r\nError: {ex.Message}\r\n");
            }
            catch (Exception ex)
            {
                sb.Append($"Server:        {server}\r\n\r\nError: {ex.Message}\r\n");
            }
            var txt = sb.ToString();
            Sync(() =>
            {
                DOut.Text = txt;
                SetStatus("DNS query done.");
            });
        });
    }

    void StartDnsSpeed(object sender, RoutedEventArgs e)
    {
        IPEndPoint server;
        try { server = DnsCmd.ServerAddr(DsServer.Text, UseV6); }
        catch (Exception ex)
        {
            SetStatus("error: " + ex.Message);
            return;
        }
        var name = DsName.Text.Trim();
        var qt = DnsWire.TypeCode("HINFO");
        StartSpeed(dsJob, dsData, DsChart, DsStats, null, "DNS speed test", Dur(Atof(DsInt.Text, 5)), () =>
        {
            try
            {
                var (rtt, ans) = DnsWire.Query(server, name, qt, TimeSpan.FromSeconds(3));
                return (Ms(rtt), ans.Count > 0 ? ans[0] : "", null);
            }
            catch (Exception ex)
            {
                return (0, "", ex.Message);
            }
        });
    }

    void StopDnsSpeed(object sender, RoutedEventArgs e) => dsJob.Halt();

    // ---- dhcp ----

    void StartDhcp(object sender, RoutedEventArgs e)
    {
        var sel = DhIf.Text.Trim();
        IPAddress? srcIP = null;
        var name = "";
        if (sel != "" && sel != "(automatic)")
        {
            name = sel;
            var i = sel.LastIndexOf('(');
            if (i >= 0)
            {
                name = sel[..i].Trim();
                if (IPAddress.TryParse(sel[(i + 1)..].Trim('(', ')', ' '), out var ip)) srcIP = ip;
            }
        }
        var o = new DhcpOpts { Iface = name, SrcIP = srcIP, IPv6 = UseV6 };
        StartSpeed(dhJob, dhData, DhChart, DhStats, DhOut, "DHCP speed test", Dur(Atof(DhInt.Text, 1)), () =>
        {
            try
            {
                var res = DhcpProbe.Probe(o);
                var info = $"{res.TypeText} from {res.ServerText}";
                if (res.Method != "") info += "  [" + res.Method + "]";
                var sum = res.ServerSummary();
                if (sum != "") info += "  ⚠ " + sum;
                return (res.Ms, info, null);
            }
            catch (Exception ex)
            {
                return (0, "", ex.Message);
            }
        });
    }

    void StopDhcp(object sender, RoutedEventArgs e) => dhJob.Halt();

    // ---- lldp ----

    void FindNeighbour(object sender, RoutedEventArgs e)
    {
        if (!EnsureElevated("LLDP capture needs administrator rights.")) return;
        var hint = LlIf.Text.Trim();
        var wait = Dur(Atof(LlWait.Text, 35));
        LlOut.Text = "Searching for LLDP frames… this can take up to ~30 s.\r\n";
        SetStatus("Searching for LLDP…");
        var token = llJob.Start();
        Task.Run(() =>
        {
            string txt, st;
            try
            {
                var (nbs, dev) = Lldp.Once(hint, wait);
                if (nbs.Count == 0)
                {
                    txt = $"No LLDP neighbour seen on {dev}.\r\nLLDP may be disabled, or it is an unmanaged switch.";
                    st = "LLDP: no neighbour.";
                }
                else
                {
                    var sb = new StringBuilder();
                    foreach (var n in nbs) sb.Append(n.Text()).Append("\r\n");
                    txt = sb.ToString();
                    st = "LLDP done.";
                }
            }
            catch (Exception ex)
            {
                txt = "error: " + ex.Message;
                st = "LLDP error.";
            }
            if (token.IsCancellationRequested) return;
            Sync(() =>
            {
                LlOut.Text = txt;
                SetStatus(st);
            });
        });
    }
}
