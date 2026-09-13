using System.Net;
using System.Runtime.InteropServices;
using System.Text;
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

/// <summary>The native Windows window: one tab per feature, with a live chart where it makes sense.</summary>
sealed class MainForm : Form
{
    static readonly Font uiFont = new("Segoe UI", 9f);
    static readonly Font tabFont = new("Segoe UI", 10f);
    static readonly Font monoFont = new("Consolas", 9f);

    readonly ChartData pData = new("ms"), dsData = new("ms"), dhData = new("ms");
    readonly Job pJob = new(), dsJob = new(), dhJob = new(), trJob = new(), llJob = new();

    ToolStripStatusLabel status = null!;
    ComboBox ipVer = null!;

    TextBox pHost = null!, pInt = null!, pLog = null!;
    CheckBox pResolve = null!;
    Label pStats = null!;
    ChartControl pChart = null!;

    TextBox trHost = null!, trOut = null!;
    CheckBox trMon = null!, trResolve = null!;

    TextBox dName = null!, dServer = null!, dOut = null!;
    ComboBox dType = null!;

    TextBox dsName = null!, dsServer = null!, dsInt = null!;
    Label dsStats = null!;
    ChartControl dsChart = null!;

    ComboBox dhIf = null!;
    TextBox dhInt = null!, dhOut = null!;
    Label dhStats = null!;
    ChartControl dhChart = null!;

    ComboBox llIf = null!;
    TextBox llWait = null!, llOut = null!;

    // ---- startup ----

    /// <summary>Shows the native Windows window. Called for a double-click and for `nwtoolkit gui`.</summary>
    public static void RunGui()
    {
        Term.DetachConsole(); // hide the console when double-clicked
        UseColor = false;
        try
        {
            ApplicationConfiguration.Initialize();
            Application.SetColorMode(SystemColorMode.System); // follow the Windows "default app mode" (light/dark)
            Application.ThreadException += (_, e) => CrashLog(e.Exception);
            Application.Run(new MainForm());
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
    static void CrashLog(Exception e)
    {
        var msg = $"nwtoolkit {Util.Version} crash {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n{e}\n";
        var path = WriteCrash(msg);
        MessageBox.Show($"{e.Message}\n\nDetails saved to:\n{path}", "nwtoolkit - error", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

    const int EM_SETCUEBANNER = 0x1501;

    /// <summary>
    /// Strips the modern theme from a control so the classic, always-visible scrollbar
    /// with arrow buttons appears, instead of the Windows 11 scrollbar that only reveals
    /// its arrows on hover.
    /// </summary>
    static void ClassicScrollbars(Control c)
    {
        if (Application.IsDarkModeEnabled) return; // dark mode brings its own scrollbar theme; keep it
        c.HandleCreated += (_, _) =>
        {
            try { SetWindowTheme(c.Handle, "", ""); } catch { }
        };
    }

    static void CueBanner(TextBox tb, string text)
    {
        tb.HandleCreated += (_, _) =>
        {
            try { SendMessage(tb.Handle, EM_SETCUEBANNER, (IntPtr)1, text); } catch { }
        };
    }

    // ---- widget helpers ----

    static Label Lbl(string text) => new() { Text = text, AutoSize = true, Margin = new Padding(3, 7, 3, 0) };

    static CheckBox Check(string text, bool on) => new() { Text = text, Checked = on, AutoSize = true, Margin = new Padding(3, 6, 6, 0) };

    static TextBox Edit(string text, int width) => new() { Text = text, Width = width, Margin = new Padding(3, 4, 3, 3) };

    static Button Btn(string text, int minW, Action onClick)
    {
        var b = new Button { Text = text, AutoSize = true, MinimumSize = new Size(minW, 27), Margin = new Padding(3, 2, 3, 2), UseVisualStyleBackColor = true };
        b.Click += (_, _) => onClick();
        return b;
    }

    static ComboBox Combo(bool editable, int width, params string[] items)
    {
        var c = new ComboBox { Width = width, Margin = new Padding(3, 3, 3, 3), DropDownStyle = editable ? ComboBoxStyle.DropDown : ComboBoxStyle.DropDownList };
        c.Items.AddRange(items);
        if (items.Length > 0) c.SelectedIndex = 0;
        return c;
    }

    static FlowLayoutPanel Row(params Control[] controls)
    {
        var p = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, WrapContents = true, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Fill, Margin = Padding.Empty };
        p.Controls.AddRange(controls);
        return p;
    }

    static GroupBox Group(string title, Control content, int pad = 8)
    {
        var g = new FramedGroupBox { Text = title, Dock = DockStyle.Fill, Padding = new Padding(pad, pad + 4, pad, pad), Margin = new Padding(0, 0, 0, 8) };
        content.Dock = DockStyle.Fill;
        g.Controls.Add(content);
        return g;
    }

    static GroupBox SettingsGroup(Control row)
    {
        var g = Group("Settings", row, 10);
        g.AutoSize = true;
        g.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        return g;
    }

    static TextBox LogBox()
    {
        var t = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = monoFont, Dock = DockStyle.Fill, BackColor = ChartControl.PlotBackground, ForeColor = ChartControl.PlotForeground };
        ClassicScrollbars(t);
        return t;
    }

    /// <summary>Label above a chart, then the chart itself filling the rest.</summary>
    static TableLayoutPanel Stack(params (Control Ctl, SizeType Type, float Size)[] rows)
    {
        var t = new TableLayoutPanel { ColumnCount = 1, Dock = DockStyle.Fill, Margin = Padding.Empty };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        foreach (var (ctl, type, size) in rows)
        {
            t.RowStyles.Add(new RowStyle(type, size));
            ctl.Dock = DockStyle.Fill;
            t.Controls.Add(ctl, 0, t.RowCount++);
        }
        return t;
    }

    static TabPage Page(string title, params (Control Ctl, SizeType Type, float Size)[] rows)
    {
        var page = new TabPage(title) { Font = uiFont, Padding = new Padding(10), UseVisualStyleBackColor = true };
        page.Controls.Add(Stack(rows));
        return page;
    }

    // ---- state helpers ----

    void Sync(Action f)
    {
        if (IsDisposed || !IsHandleCreated) return;
        try { BeginInvoke(f); } catch (ObjectDisposedException) { } catch (InvalidOperationException) { }
    }

    void SetStatus(string s) => status.Text = s;

    /// <summary>Opens a web address in the default browser.</summary>
    static void OpenUrl(string url)
    {
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return;
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { }
    }

    bool UseV6 => ipVer.SelectedIndex == 1;

    static double Atof(string s, double def) =>
        double.TryParse(s.Trim().Replace(',', '.'), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : def;

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
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return false;
        try
        {
            Elevation.RelaunchAsAdmin(new[] { "gui" });
        }
        catch (Exception e)
        {
            MessageBox.Show(this, "Restarting as administrator failed:\n" + e.Message, "Could not restart", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
        Environment.Exit(0);
        return false;
    }

    /// <summary>Runs a measurement every interval on a background thread and feeds the chart, stats line and log.</summary>
    void StartSpeed(Job j, ChartData cd, ChartControl chart, Label stats, TextBox? log, string name, TimeSpan interval,
        Func<(double Value, string Info, string? Error)> measure)
    {
        var token = j.Start();
        cd.Reset();
        chart.Invalidate();
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
                    chart.Invalidate();
                    if (log != null)
                    {
                        var ts = DateTime.Now.ToString("HH:mm:ss");
                        log.AppendText(err != null ? $"{ts}  error: {err}\r\n" : $"{ts}  {v.F(2)} {cd.Unit}   {info}\r\n");
                    }
                });
                if (token.WaitHandle.WaitOne(interval)) break;
            }
            Sync(() => SetStatus(name + " stopped."));
        });
    }

    // ---- the window ----

    public MainForm()
    {
        Text = $"nwtoolkit {Util.Version} — network diagnostics";
        Font = uiFont;
        // All sizes below are in 96-dpi pixels; WinForms scales them to the screen's dpi.
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        MinimumSize = new Size(640, 420);
        Size = new Size(1100, 740);
        StartPosition = FormStartPosition.WindowsDefaultLocation;
        LoadIcon();

        // FramedTabControl repaints the bright page frame grey in dark mode.
        var tabs = new FramedTabControl { Dock = DockStyle.Fill, Font = tabFont };
        tabs.TabPages.AddRange(new[] { BuildPingPage(), BuildTracePage(), BuildDnsPage(), BuildDnsSpeedPage(), BuildDhcpPage(), BuildLldpPage(), BuildAboutPage() });

        // The IP version choice sits on the tab strip itself, at the right, so it does
        // not cost a row of its own: a small panel laid over the TabControl's header area.
        ipVer = Combo(false, 90, "IPv4", "IPv6");
        var top = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Anchor = AnchorStyles.Top | AnchorStyles.Right, Margin = Padding.Empty, Padding = Padding.Empty };
        var ipLabel = Lbl("IP version:");
        ipLabel.Margin = new Padding(0, 6, 4, 0);
        ipVer.Margin = new Padding(0, 2, 0, 0);
        top.Controls.Add(ipLabel);
        top.Controls.Add(ipVer);

        status = new ToolStripStatusLabel("Ready.") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        var strip = new StatusStrip { SizingGrip = true };
        strip.Items.Add(status);

        Controls.Add(tabs);
        Controls.Add(top);
        Controls.Add(strip);
        top.BringToFront();

        void PlaceIpVersion()
        {
            var margin = (int)(12 * DeviceDpi / 96f);
            // The window must at least fit every tab header plus the picker, or they overlap.
            var tabsRight = tabs.TabCount > 0 ? tabs.GetTabRect(tabs.TabCount - 1).Right : 0;
            var needClientW = tabsRight + top.Width + 3 * margin;
            var chrome = Width - ClientSize.Width;
            if (MinimumSize.Width < needClientW + chrome) MinimumSize = new Size(needClientW + chrome, MinimumSize.Height);
            if (ClientSize.Width < needClientW) ClientSize = new Size(needClientW, ClientSize.Height);

            var headerH = tabs.DisplayRectangle.Y; // height of the tab strip above the pages
            top.Left = ClientSize.Width - top.Width - margin;
            top.Top = Math.Max(0, (headerH - top.Height) / 2);
        }
        Load += (_, _) =>
        {
            PlaceIpVersion();
            PopulateInterfaces();
        };
        DpiChanged += (_, _) => PlaceIpVersion();
        FormClosing += (_, _) =>
        {
            pJob.Halt();
            dsJob.Halt();
            dhJob.Halt();
            trJob.Halt();
            llJob.Halt();
        };
    }

    void LoadIcon()
    {
        try
        {
            using var s = typeof(MainForm).Assembly.GetManifestResourceStream("nwtoolkit.ico");
            if (s != null) Icon = new Icon(s);
        }
        catch { }
    }

    void PopulateInterfaces()
    {
        // DHCP interface list from the real NICs
        dhIf.Items.Clear();
        dhIf.Items.Add("(automatic)");
        foreach (var ic in Dhcp.UsableIPv4Ifaces()) dhIf.Items.Add($"{ic.Name}  ({ic.Ip})");
        dhIf.SelectedIndex = 0;

        Task.Run(() =>
        {
            var (_, devs, _) = Lldp.Open("");
            if (devs.Count > 0) Sync(() => llIf.Items.AddRange(devs.ToArray()));
        });
    }

    TabPage BuildPingPage()
    {
        pHost = Edit("1.1.1.1", 190);
        pInt = Edit("1", 60);
        pResolve = Check("resolve names (DNS)", false);
        var settings = SettingsGroup(Row(Lbl("Host / IP:"), pHost, Lbl("Interval (s):"), pInt, pResolve,
            Btn("Start", 90, StartPing), Btn("Stop", 90, () => pJob.Halt())));

        pStats = new Label { Text = "Ready.", AutoSize = true };
        pChart = new ChartControl { Data = pData, MinimumSize = new Size(0, 120) };
        var chart = Group("Response time (ms)", Stack((pStats, SizeType.AutoSize, 0), (pChart, SizeType.Percent, 100)));

        pLog = LogBox();
        var log = Group("Log", pLog);

        return Page("Ping", (settings, SizeType.AutoSize, 0), (chart, SizeType.Percent, 100), (log, SizeType.Absolute, 140));
    }

    void StartPing()
    {
        IPAddress ip;
        try { ip = ResolveIP(pHost.Text, UseV6); }
        catch (Exception e)
        {
            SetStatus("error: " + e.Message);
            return;
        }
        var echo = new Echo();
        var payload = Encoding.ASCII.GetBytes("nwtoolkit");
        var resolve = pResolve.Checked;
        StartSpeed(pJob, pData, pChart, pStats, pLog, "Ping", Dur(Atof(pInt.Text, 1)), () =>
        {
            var r = echo.Send(ip, 128, TimeSpan.FromSeconds(2), payload);
            if (r.Error != null) return (0, "", r.Error);
            if (r.Status != System.Net.NetworkInformation.IPStatus.Success) return (0, "", Echo.StatusText(r.Status));
            var from = r.Peer == null ? "?" : resolve ? ReverseDns.Label(r.Peer) : r.Peer.ToString();
            return (r.Ms, "from " + from, null);
        });
    }

    TabPage BuildTracePage()
    {
        trHost = Edit("example.com", 220);
        trMon = Check("monitor continuously", false);
        trResolve = Check("resolve names (DNS)", true);
        var settings = SettingsGroup(Row(Lbl("Host / IP:"), trHost, trMon, trResolve,
            Btn("Start", 90, StartTrace), Btn("Stop", 90, () => trJob.Halt())));
        trOut = LogBox();
        var route = Group("Route (times in ms)", trOut);
        return Page("Traceroute", (settings, SizeType.AutoSize, 0), (route, SizeType.Percent, 100));
    }

    void StartTrace()
    {
        IPAddress dst;
        try { dst = ResolveIP(trHost.Text, UseV6); }
        catch (Exception e)
        {
            trOut.Text = "error: " + e.Message;
            return;
        }
        var host = trHost.Text;
        var mon = trMon.Checked;
        var resolve = trResolve.Checked;
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
                    trOut.Text = txt;
                    SetStatus("Traceroute done.");
                });
                if (!mon) return;
                if (token.WaitHandle.WaitOne(TimeSpan.FromSeconds(3))) return;
            }
        });
    }

    TabPage BuildDnsPage()
    {
        dName = Edit("example.com", 190);
        dServer = Edit("", 140);
        CueBanner(dServer, "empty = system");
        dType = Combo(false, 80, "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR");
        var settings = SettingsGroup(Row(Lbl("Name:"), dName, Lbl("Server:"), dServer, Lbl("Type:"), dType, Btn("Query", 90, RunDnsQuery)));
        dOut = LogBox();
        var answer = Group("Answer", dOut);
        return Page("DNS query", (settings, SizeType.AutoSize, 0), (answer, SizeType.Percent, 100));
    }

    void RunDnsQuery()
    {
        IPEndPoint server;
        try { server = DnsCmd.ServerAddr(dServer.Text, UseV6); }
        catch (Exception e)
        {
            dOut.Text = "error: " + e.Message;
            return;
        }
        var qt = DnsWire.TypeCode(dType.Text);
        var name = dName.Text.Trim();
        dOut.Text = "working…";
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
            catch (DnsRcodeException e)
            {
                sb.Append($"Server:        {server}\r\nResponse time: {Ms(e.Rtt).F(2)} ms\r\n\r\nError: {e.Message}\r\n");
            }
            catch (Exception e)
            {
                sb.Append($"Server:        {server}\r\n\r\nError: {e.Message}\r\n");
            }
            var txt = sb.ToString();
            Sync(() =>
            {
                dOut.Text = txt;
                SetStatus("DNS query done.");
            });
        });
    }

    TabPage BuildDnsSpeedPage()
    {
        dsName = Edit("example.com", 190);
        dsServer = Edit("", 140);
        CueBanner(dsServer, "empty = system");
        dsInt = Edit("5", 60);
        var settings = SettingsGroup(Row(Lbl("Name:"), dsName, Lbl("Server:"), dsServer, Lbl("Interval (s):"), dsInt,
            Btn("Start", 90, StartDnsSpeed), Btn("Stop", 90, () => dsJob.Halt())));
        dsStats = new Label { Text = "Ready.", AutoSize = true };
        dsChart = new ChartControl { Data = dsData, MinimumSize = new Size(0, 140) };
        var chart = Group("Response time (ms)", Stack((dsStats, SizeType.AutoSize, 0), (dsChart, SizeType.Percent, 100)));
        return Page("DNS speed test", (settings, SizeType.AutoSize, 0), (chart, SizeType.Percent, 100));
    }

    void StartDnsSpeed()
    {
        IPEndPoint server;
        try { server = DnsCmd.ServerAddr(dsServer.Text, UseV6); }
        catch (Exception e)
        {
            SetStatus("error: " + e.Message);
            return;
        }
        var name = dsName.Text.Trim();
        var qt = DnsWire.TypeCode("HINFO");
        StartSpeed(dsJob, dsData, dsChart, dsStats, null, "DNS speed test", Dur(Atof(dsInt.Text, 5)), () =>
        {
            try
            {
                var (rtt, ans) = DnsWire.Query(server, name, qt, TimeSpan.FromSeconds(3));
                return (Ms(rtt), ans.Count > 0 ? ans[0] : "", null);
            }
            catch (Exception e)
            {
                return (0, "", e.Message);
            }
        });
    }

    TabPage BuildDhcpPage()
    {
        dhIf = Combo(true, 220);
        dhInt = Edit("1", 50);
        var settings = SettingsGroup(Row(Lbl("Interface:"), dhIf, Lbl("Interval (s):"), dhInt,
            Btn("Start", 90, StartDhcp), Btn("Stop", 90, () => dhJob.Halt())));
        dhStats = new Label { Text = "Ready.", AutoSize = true };
        dhChart = new ChartControl { Data = dhData, MinimumSize = new Size(0, 130) };
        dhOut = LogBox();
        var chart = Group("Response time (ms)", Stack((dhStats, SizeType.AutoSize, 0), (dhChart, SizeType.Percent, 100), (dhOut, SizeType.Absolute, 90)));
        return Page("DHCP speed test", (settings, SizeType.AutoSize, 0), (chart, SizeType.Percent, 100));
    }

    void StartDhcp()
    {
        var sel = dhIf.Text.Trim();
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
        StartSpeed(dhJob, dhData, dhChart, dhStats, dhOut, "DHCP speed test", Dur(Atof(dhInt.Text, 1)), () =>
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
            catch (Exception e)
            {
                return (0, "", e.Message);
            }
        });
    }

    TabPage BuildLldpPage()
    {
        llIf = Combo(true, 260);
        llWait = Edit("35", 60);
        var settings = SettingsGroup(Row(Lbl("Interface:"), llIf, Lbl("Wait (s):"), llWait, Btn("Find neighbour", 110, FindNeighbour)));
        llOut = LogBox();
        var found = Group("Connected switch/port", llOut);
        return Page("LLDP neighbour", (settings, SizeType.AutoSize, 0), (found, SizeType.Percent, 100));
    }

    void FindNeighbour()
    {
        if (!EnsureElevated("LLDP capture needs administrator rights.")) return;
        var hint = llIf.Text.Trim();
        var wait = Dur(Atof(llWait.Text, 35));
        llOut.Text = "Searching for LLDP frames… this can take up to ~30 s.\r\n";
        SetStatus("Searching for LLDP…");
        var token = llJob.Start();
        Task.Run(() =>
        {
            string txt;
            string st;
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
            catch (Exception e)
            {
                txt = "error: " + e.Message;
                st = "LLDP error.";
            }
            if (token.IsCancellationRequested) return;
            Sync(() =>
            {
                llOut.Text = txt;
                SetStatus(st);
            });
        });
    }

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

    TabPage BuildAboutPage()
    {
        var title = new Label { Text = "nwtoolkit " + Util.Version, Font = new Font("Segoe UI", 15f, FontStyle.Bold), AutoSize = true, Margin = new Padding(0, 0, 0, 6) };
        // A RichTextBox rather than a TextBox: it recognises the URL and makes it clickable.
        // Its height follows the text, so the whole paragraph is always visible.
        var about = new RichTextBox
        {
            ReadOnly = true, DetectUrls = true, TabStop = false, Font = uiFont, BorderStyle = BorderStyle.FixedSingle,
            BackColor = ChartControl.PlotBackground, ForeColor = ChartControl.PlotForeground,
            ScrollBars = RichTextBoxScrollBars.None, Margin = new Padding(0, 0, 0, 4),
            Text = "Network diagnostic tool for IPv4, IPv6 and LLDP.  Made by vibe coding using Anthropic's Claude*.\r\n\r\n" +
                   "Software is licensed under the MIT license. If you have any suggestions, bug fixes or want to\r\n" +
                   "get in touch, visit https://github.com/bruijnes/\r\n\r\n" +
                   "* Claude is a trademark of Anthropic, PBC.",
        };
        about.ContentsResized += (_, e) => about.Height = e.NewRectangle.Height + (int)(12 * DeviceDpi / 96f);
        about.LinkClicked += (_, e) => OpenUrl(e.LinkText ?? "");
        var licTitle = new Label { Text = "MIT license", Font = new Font("Segoe UI", 9f, FontStyle.Bold), AutoSize = true, Margin = new Padding(0, 8, 0, 4) };
        var lic = LogBox();
        lic.Text = MitLicense;
        lic.Select(0, 0);
        var page = Page("About", (title, SizeType.AutoSize, 0), (about, SizeType.AutoSize, 0), (licTitle, SizeType.AutoSize, 0), (lic, SizeType.Percent, 100));
        page.Padding = new Padding(18);
        return page;
    }
}
