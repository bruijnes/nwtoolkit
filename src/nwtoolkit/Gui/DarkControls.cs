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
    const int WM_PAINT = 0x000F;

    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if (m.Msg == WM_PAINT && DarkFrame.Active && IsHandleCreated) PaintFrame();
    }

    /// <summary>Covers the page frame the control just painted with the grey one.</summary>
    void PaintFrame()
    {
        try
        {
            using var g = Graphics.FromHwnd(Handle);
            var outer = ClientRectangle;
            var page = DisplayRectangle;
            using var fill = new SolidBrush(BackColor);
            using var pen = new Pen(DarkFrame.Colour);

            // strip between the tab headers and the page, plus left, right and bottom strips
            var headerBottom = TabCount > 0 && SelectedIndex >= 0 ? GetTabRect(SelectedIndex).Bottom : page.Top;
            g.FillRectangle(fill, outer.Left, headerBottom, outer.Width, page.Top - headerBottom);
            g.FillRectangle(fill, outer.Left, page.Top, page.Left - outer.Left, outer.Bottom - page.Top);
            g.FillRectangle(fill, page.Right, page.Top, outer.Right - page.Right, outer.Bottom - page.Top);
            g.FillRectangle(fill, outer.Left, page.Bottom, outer.Width, outer.Bottom - page.Bottom);

            // one thin grey line around the page
            g.DrawRectangle(pen, page.Left - 1, page.Top - 1, page.Width + 1, page.Height + 1);
        }
        catch
        {
            // painting is best effort; a missed frame is repainted on the next WM_PAINT
        }
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
