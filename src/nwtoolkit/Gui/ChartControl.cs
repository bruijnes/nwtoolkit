using System.Drawing.Drawing2D;
using System.Globalization;

namespace Nwtoolkit.Gui;

/// <summary>Thread-safe sample store behind a live chart.</summary>
sealed class ChartData
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
/// Line chart of response times. With more samples than pixels each column becomes a
/// min/max band with an average line, so a long run still reads well.
/// </summary>
sealed class ChartControl : Control
{
    public ChartData? Data;
    static readonly Font axisFont = new("Segoe UI", 8f);

    /// <summary>Chart colours for the light and the dark app mode.</summary>
    sealed record Palette(Color Bg, Color Border, Color Grid, Color Line, Color Band, Color Text);

    static readonly Palette light = new(
        Bg: Color.FromArgb(0xf0, 0xf0, 0xf0), // same grey as the log box
        Border: Color.FromArgb(0xc8, 0xcc, 0xd0),
        Grid: Color.FromArgb(0xe6, 0xe8, 0xea),
        Line: Color.FromArgb(0x19, 0x4b, 0x4d),
        Band: Color.FromArgb(0xbf, 0xd6, 0xd7),
        Text: Color.FromArgb(0x6a, 0x70, 0x78));

    static readonly Palette dark = new(
        Bg: Color.FromArgb(0x3c, 0x3c, 0x3c),     // a shade lighter than the window, so the plot stands out
        Border: Color.FromArgb(0x6a, 0x6e, 0x72),
        Grid: Color.FromArgb(0x50, 0x54, 0x58),
        Line: Color.FromArgb(0xf4, 0xf4, 0xf4),   // white line for contrast
        Band: Color.FromArgb(0x8c, 0x90, 0x94),
        Text: Color.FromArgb(0xd0, 0xd4, 0xd8));

    public ChartControl()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var b = ClientRectangle;
        var p = Application.IsDarkModeEnabled ? dark : light;
        g.Clear(p.Bg);
        using var border = new Pen(p.Border);
        g.DrawRectangle(border, b.X, b.Y, b.Width - 1, b.Height - 1);
        if (Data == null) return;
        var (vals, times, _, _) = Data.Snapshot();

        var scale = DeviceDpi / 96f;
        int padL = (int)(60 * scale), padT = (int)(14 * scale), padB = (int)(36 * scale), padR = (int)(14 * scale);
        var x0 = b.X + padL;
        var y0 = b.Y + padT;
        var plotW = b.Width - padL - padR;
        var plotH = b.Height - padT - padB;
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

        int Gx(int i, int n) => n < 2 ? x0 : x0 + (int)((long)plotW * i / (n - 1));
        int Gy(double v) => y0 + plotH - (int)(plotH * ((v - mn) / (mx - mn)));

        using var grid = new Pen(p.Grid);
        using var textBrush = new SolidBrush(p.Text);
        using var fmtRight = new StringFormat { Alignment = StringAlignment.Far, LineAlignment = StringAlignment.Center, FormatFlags = StringFormatFlags.NoWrap | StringFormatFlags.NoClip };
        for (var k = 0; k <= 4; k++)
        {
            var vy = mn + (mx - mn) * k / 4;
            var yy = Gy(vy);
            g.DrawLine(grid, x0, yy, x0 + plotW, yy);
            g.DrawString(vy.ToString("F1", CultureInfo.InvariantCulture), axisFont, textBrush,
                new RectangleF(b.X + 6 * scale, yy - 9 * scale, padL - 14 * scale, 18 * scale), fmtRight);
        }

        var n = vals.Length;
        using var linePen = new Pen(p.Line, 2f);
        if (n >= 2 && n <= plotW)
        {
            // enough width: a plain line through every point
            var pts = new Point[n];
            for (var i = 0; i < n; i++) pts[i] = new Point(Gx(i, n), Gy(vals[i]));
            g.DrawLines(linePen, pts);
        }
        else if (n > plotW)
        {
            // more samples than pixels: compress per column into a min/max band plus an average line
            using var bandPen = new Pen(p.Band);
            var avgPts = new List<Point>(plotW);
            for (var cix = 0; cix < plotW; cix++)
            {
                var lo = (int)((long)cix * n / plotW);
                var hi = (int)((long)(cix + 1) * n / plotW);
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
                var x = x0 + cix;
                g.DrawLine(bandPen, x, Gy(mxv), x, Gy(mnv));
                avgPts.Add(new Point(x, Gy(sum / (hi - lo))));
            }
            if (avgPts.Count >= 2) g.DrawLines(linePen, avgPts.ToArray());
        }

        // x axis: time labels along the bottom, the clock time of each sample
        if (n >= 2)
        {
            var yLab = y0 + plotH + 5 * scale;
            using var axisTick = new Pen(p.Border);
            var ticks = plotW < 360 * scale ? 3 : 5;
            for (var t = 0; t <= ticks; t++)
            {
                var i = (n - 1) * t / ticks;
                var x = Gx(i, n);
                g.DrawLine(axisTick, x, y0 + plotH, x, y0 + plotH + 3);
                var lbl = times[i].ToString("HH:mm:ss", CultureInfo.InvariantCulture);
                var w = 60 * scale;
                float bx = x - w / 2;
                var align = StringAlignment.Center;
                if (t == 0)
                {
                    bx = x;
                    align = StringAlignment.Near;
                }
                else if (t == ticks)
                {
                    bx = x - w;
                    align = StringAlignment.Far;
                }
                using var fmt = new StringFormat { Alignment = align, LineAlignment = StringAlignment.Near, FormatFlags = StringFormatFlags.NoWrap | StringFormatFlags.NoClip };
                g.DrawString(lbl, axisFont, textBrush, new RectangleF(bx, yLab, w, 16 * scale), fmt);
            }
        }
    }
}
