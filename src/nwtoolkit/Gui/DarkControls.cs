using System.Runtime.InteropServices;

namespace Nwtoolkit.Gui;

/// <summary>
/// The native tab control and group box draw bright white frames in dark mode. These
/// two subclasses repaint those frames in a quiet grey; in light mode they leave the
/// standard rendering alone.
/// </summary>
static class DarkFrame
{
    public static readonly Color Colour = Color.FromArgb(0x55, 0x59, 0x5d);
    public static bool Active => Application.IsDarkModeEnabled;
}

sealed class FramedTabControl : TabControl
{
    const int TCM_ADJUSTRECT = 0x1328;

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int Left, Top, Right, Bottom; }

    /// <summary>
    /// When the control computes where the page goes (TCM_ADJUSTRECT, wParam 0), the
    /// answer is widened to the control's own edges, just below the tab headers. The
    /// page then covers the frame the control paints, so the frame is never seen.
    /// </summary>
    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if (m.Msg != TCM_ADJUSTRECT || m.WParam != IntPtr.Zero || !DarkFrame.Active || m.LParam == IntPtr.Zero) return;
        var rc = Marshal.PtrToStructure<RECT>(m.LParam);
        var headerBottom = TabCount > 0 ? GetTabRect(Math.Max(0, SelectedIndex)).Bottom : rc.Top;
        rc.Left = 0;
        rc.Right = Width;
        rc.Bottom = Height;
        rc.Top = Math.Min(rc.Top, headerBottom);
        Marshal.StructureToPtr(rc, m.LParam, false);
    }
}

sealed class FramedGroupBox : GroupBox
{
    protected override void OnPaint(PaintEventArgs e)
    {
        if (!DarkFrame.Active)
        {
            base.OnPaint(e);
            return;
        }
        var g = e.Graphics;
        g.Clear(BackColor);
        var text = Text;
        var textSize = TextRenderer.MeasureText(g, text, Font);
        var r = ClientRectangle;
        var y = textSize.Height / 2;
        var gap = (int)(8 * DeviceDpi / 96f);
        using var pen = new Pen(DarkFrame.Colour);
        g.DrawLine(pen, r.Left, y, r.Left + gap, y);
        g.DrawLine(pen, r.Left + gap + textSize.Width + 2, y, r.Right - 1, y);
        g.DrawLine(pen, r.Left, y, r.Left, r.Bottom - 1);
        g.DrawLine(pen, r.Right - 1, y, r.Right - 1, r.Bottom - 1);
        g.DrawLine(pen, r.Left, r.Bottom - 1, r.Right - 1, r.Bottom - 1);
        TextRenderer.DrawText(g, text, Font, new Point(r.Left + gap + 1, 0), ForeColor, TextFormatFlags.NoPadding);
    }
}
