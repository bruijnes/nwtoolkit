using System.Globalization;
using System.Windows;
using System.Windows.Media;

namespace Nwtoolkit.Gui;

/// <summary>Thread-safe sample store behind a live chart.</summary>
public sealed class ChartData
{
    readonly object mu = new();
    readonly List<double> vals = new();
    readonly List<DateTime> times = new();
    int lost, n;
    public readonly string Unit;

    public ChartData(string unit) => Unit = unit;

    public void Push(double v, bool ok)
    {
        lock (mu)
        {
            n++;
            if (!ok)
            {
                lost++;
                return;
            }
            vals.Add(v);
            times.Add(DateTime.Now);
            const int keep = 50000; // generous history; the chart compresses to the available width
            if (vals.Count > keep)
            {
                vals.RemoveRange(0, vals.Count - keep);
                times.RemoveRange(0, times.Count - keep);
            }
        }
    }

    public (double[] Vals, DateTime[] Times, int Lost, int N) Snapshot()
    {
        lock (mu) return (vals.ToArray(), times.ToArray(), lost, n);
    }

    public void Reset()
    {
        lock (mu)
        {
            vals.Clear();
            times.Clear();
            lost = n = 0;
        }
    }

    public static string StatsText(double[] vals, int lost, int n, string unit)
    {
        if (vals.Length == 0)
            return n == 0 ? "Ready." : $"samples: {n}   errors: {lost}";
        double mn = vals[0], mx = vals[0], sum = 0;
        foreach (var v in vals)
        {
            sum += v;
            if (v < mn) mn = v;
            if (v > mx) mx = v;
        }
        var avg = sum / vals.Length;
        var loss = lost * 100.0 / n;
        return $"last {vals[^1].F(2)} {unit}     min {mn.F(2)}     avg {avg.F(2)}     max {mx.F(2)} {unit}     loss {loss.F(0)}%     samples {n}";
    }
}

/// <summary>
/// Line chart of response times, drawn directly with a DrawingContext. With more
/// samples than pixels each column becomes a min/max band with an average line, so a
/// long run still reads well. Colours come from the active Fluent theme, so the chart
/// follows light and dark mode; the line itself is teal in light mode and mint in dark.
/// </summary>
public sealed class ChartControl : FrameworkElement
{
    public ChartData? Data { get; set; }

    static readonly Typeface axisFace = new("Segoe UI");
    const double axisFontSize = 11; // ~8pt

    /// <summary>The plot area brush for the current theme; the output boxes use it too.</summary>
    public static Brush PlotBackground(FrameworkElement fe) => Theme.IsDark(fe) ? new SolidColorBrush(Color.FromRgb(0x3c, 0x3c, 0x3c)) : new SolidColorBrush(Color.FromRgb(0xf0, 0xf0, 0xf0));

    protected override void OnRender(DrawingContext dc)
    {
        var w = ActualWidth;
        var h = ActualHeight;
        if (w < 1 || h < 1) return;
        var dark = Theme.IsDark(this);
        var bg = PlotBackground(this);
        var border = Pen(dark ? Color.FromRgb(0x6a, 0x6e, 0x72) : Color.FromRgb(0xc8, 0xcc, 0xd0));
        var grid = Pen(dark ? Color.FromRgb(0x50, 0x54, 0x58) : Color.FromRgb(0xe6, 0xe8, 0xea));
        var line = Pen(dark ? Color.FromRgb(0x6f, 0xc7, 0xcb) : Color.FromRgb(0x19, 0x4b, 0x4d), 2);
        var band = Pen(dark ? Color.FromRgb(0x4a, 0x78, 0x7a) : Color.FromRgb(0xbf, 0xd6, 0xd7));
        var text = new SolidColorBrush(dark ? Color.FromRgb(0xd0, 0xd4, 0xd8) : Color.FromRgb(0x6a, 0x70, 0x78));

        dc.DrawRectangle(bg, border, new Rect(0.5, 0.5, w - 1, h - 1));
        if (Data == null) return;
        var (vals, times, _, _) = Data.Snapshot();

        double padL = 60, padT = 14, padB = 36, padR = 14;
        var x0 = padL;
        var y0 = padT;
        var plotW = w - padL - padR;
        var plotH = h - padT - padB;
        if (plotW < 40 || plotH < 30) return;

        double mn = 0, mx = 1;
        if (vals.Length > 0)
        {
            mn = mx = vals[0];
            foreach (var v in vals)
            {
                if (v < mn) mn = v;
                if (v > mx) mx = v;
            }
        }
        if (mx - mn < 1) mx = mn + 1;
        var rng = mx - mn;
        mn -= rng * 0.1;
        mx += rng * 0.1;
        if (mn < 0) mn = 0;

        double Gx(int i, int n) => n < 2 ? x0 : x0 + plotW * i / (n - 1);
        double Gy(double v) => Math.Round(y0 + plotH - plotH * ((v - mn) / (mx - mn))) + 0.5;
        var dip = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        for (var k = 0; k <= 4; k++)
        {
            var vy = mn + (mx - mn) * k / 4;
            var yy = Gy(vy);
            dc.DrawLine(grid, new Point(x0, yy), new Point(x0 + plotW, yy));
            var ft = new FormattedText(vy.ToString("F1", CultureInfo.InvariantCulture), CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight, axisFace, axisFontSize, text, dip);
            dc.DrawText(ft, new Point(x0 - 8 - ft.Width, yy - ft.Height / 2));
        }

        var n = vals.Length;
        var cols = (int)plotW;
        if (n >= 2 && n <= cols)
        {
            // enough width: a plain line through every point
            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                g.BeginFigure(new Point(Gx(0, n), Gy(vals[0])), false, false);
                for (var i = 1; i < n; i++) g.LineTo(new Point(Gx(i, n), Gy(vals[i])), true, true);
            }
            geo.Freeze();
            dc.DrawGeometry(null, line, geo);
        }
        else if (n > cols)
        {
            // more samples than pixels: compress per column into a min/max band plus an average line
            var geo = new StreamGeometry();
            using (var g = geo.Open())
            {
                var first = true;
                for (var cix = 0; cix < cols; cix++)
                {
                    var lo = (int)((long)cix * n / cols);
                    var hi = (int)((long)(cix + 1) * n / cols);
                    if (hi <= lo) hi = lo + 1;
                    if (hi > n) hi = n;
                    double mnv = vals[lo], mxv = vals[lo], sum = 0;
                    for (var j = lo; j < hi; j++)
                    {
                        var v = vals[j];
                        if (v < mnv) mnv = v;
                        if (v > mxv) mxv = v;
                        sum += v;
                    }
                    var x = x0 + cix + 0.5;
                    dc.DrawLine(band, new Point(x, Gy(mxv)), new Point(x, Gy(mnv)));
                    var p = new Point(x, Gy(sum / (hi - lo)));
                    if (first) g.BeginFigure(p, false, false);
                    else g.LineTo(p, true, true);
                    first = false;
                }
            }
            geo.Freeze();
            dc.DrawGeometry(null, line, geo);
        }

        // x axis: time labels along the bottom, the clock time of each sample
        if (n >= 2)
        {
            var yLab = y0 + plotH + 5;
            var ticks = plotW < 360 ? 3 : 5;
            for (var t = 0; t <= ticks; t++)
            {
                var i = (n - 1) * t / ticks;
                var x = Math.Round(Gx(i, n)) + 0.5;
                dc.DrawLine(border, new Point(x, y0 + plotH), new Point(x, y0 + plotH + 3));
                var ft = new FormattedText(times[i].ToString("HH:mm:ss", CultureInfo.InvariantCulture), CultureInfo.InvariantCulture,
                    FlowDirection.LeftToRight, axisFace, axisFontSize, text, dip);
                var bx = t == 0 ? x : t == ticks ? x - ft.Width : x - ft.Width / 2;
                dc.DrawText(ft, new Point(bx, yLab));
            }
        }
    }

    static Pen Pen(Color c, double thickness = 1)
    {
        var p = new Pen(new SolidColorBrush(c), thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round, LineJoin = PenLineJoin.Round };
        p.Freeze();
        return p;
    }
}

/// <summary>Tells light from dark by looking at the theme's text colour.</summary>
public static class Theme
{
    public static bool IsDark(FrameworkElement fe)
    {
        var brush = fe.TryFindResource("TextFillColorPrimaryBrush") as SolidColorBrush
                    ?? Application.Current?.TryFindResource("TextFillColorPrimaryBrush") as SolidColorBrush;
        if (brush == null) return false;
        var c = brush.Color;
        var luminance = (0.299 * c.R + 0.587 * c.G + 0.114 * c.B) / 255.0;
        return luminance > 0.5; // light text means a dark background
    }
}
