using System.Globalization;
using System.Text;

namespace Nwtoolkit;

/// <summary>
/// Line chart in box-drawing characters for the console monitors, a port of the
/// asciigraph plot: interpolate the series to the width, scale to the height, then
/// draw with ╭ ╮ ╰ ╯ │ ─ and a labelled axis.
/// </summary>
public static class AsciiGraph
{
    public static string Plot(IReadOnlyList<double> input, int height, int width, string caption = "")
    {
        if (input.Count == 0) return "";
        var series = width > 0 && input.Count > 1 ? Interpolate(input, width) : input.ToArray();
        var len = series.Length;
        var minimum = series.Min();
        var maximum = series.Max();
        var interval = Math.Abs(maximum - minimum);
        if (height <= 0) height = interval <= 0 ? 1 : (int)interval;
        const int offset = 3;
        var ratio = interval != 0 ? height / interval : 1;
        var min2 = Round(minimum * ratio);
        var max2 = Round(maximum * ratio);
        var intMin2 = (int)min2;
        var intMax2 = (int)max2;
        var rows = Math.Abs(intMax2 - intMin2);
        var gridW = len + offset;
        var plot = new string[rows + 1][];
        for (var i = 0; i <= rows; i++)
        {
            plot[i] = new string[gridW];
            Array.Fill(plot[i], " ");
        }

        var precision = 2;
        var logMaximum = Math.Log10(Math.Max(Math.Abs(maximum), Math.Abs(minimum)));
        if (minimum == 0 && maximum == 0) logMaximum = -1;
        if (logMaximum < 0)
        {
            if (logMaximum % 1 != 0) precision += (int)Math.Abs(logMaximum);
            else precision += (int)(Math.Abs(logMaximum) - 1.0);
        }
        else if (logMaximum > 2)
        {
            precision = 0;
        }
        var maxNumLength = maximum.ToString("F" + precision, CultureInfo.InvariantCulture).Length;
        var minNumLength = minimum.ToString("F" + precision, CultureInfo.InvariantCulture).Length;
        var maxWidth = Math.Max(maxNumLength, minNumLength);

        for (var y = intMin2; y < intMax2 + 1; y++)
        {
            var magnitude = rows > 0 ? maximum - (y - intMin2) * interval / rows : y;
            var label = magnitude.ToString("F" + precision, CultureInfo.InvariantCulture).PadLeft(maxWidth + 1);
            var w = y - intMin2;
            var h = Math.Max(offset - label.Length, 0);
            plot[w][h] = label;
            plot[w][offset - 1] = y == 0 ? "┼" : "┤";
        }

        var y0 = (int)(Round(series[0] * ratio) - min2);
        plot[rows - y0][offset - 1] = "┼"; // first value
        for (var x = 0; x < len - 1; x++)
        {
            y0 = (int)(Round(series[x] * ratio) - intMin2);
            var y1 = (int)(Round(series[x + 1] * ratio) - intMin2);
            if (y0 == y1)
            {
                plot[rows - y0][x + offset] = "─";
            }
            else
            {
                if (y0 > y1)
                {
                    plot[rows - y1][x + offset] = "╰";
                    plot[rows - y0][x + offset] = "╮";
                }
                else
                {
                    plot[rows - y1][x + offset] = "╭";
                    plot[rows - y0][x + offset] = "╯";
                }
                var start = Math.Min(y0, y1) + 1;
                var end = Math.Max(y0, y1);
                for (var y = start; y < end; y++) plot[rows - y][x + offset] = "│";
            }
        }

        var lines = new StringBuilder();
        for (var h = 0; h < plot.Length; h++)
        {
            if (h != 0) lines.Append('\n');
            var lastCharIndex = 0;
            for (var i = gridW - 1; i >= 0; i--)
            {
                if (plot[h][i] != " ")
                {
                    lastCharIndex = i;
                    break;
                }
            }
            for (var i = 0; i <= lastCharIndex; i++) lines.Append(plot[h][i]);
        }
        if (caption != "")
        {
            lines.Append('\n');
            lines.Append(' ', offset + maxWidth + 2);
            if (caption.Length < len) lines.Append(' ', (len - caption.Length) / 2);
            lines.Append(caption);
        }
        return lines.ToString();
    }

    static double Round(double v) => Math.Round(v, MidpointRounding.AwayFromZero);

    static double[] Interpolate(IReadOnlyList<double> data, int fitCount)
    {
        var out_ = new double[fitCount];
        var springFactor = (data.Count - 1) / (double)(fitCount - 1);
        out_[0] = data[0];
        for (var i = 1; i < fitCount - 1; i++)
        {
            var spring = i * springFactor;
            var before = Math.Floor(spring);
            var after = Math.Ceiling(spring);
            var atPoint = spring - before;
            var a = data[(int)before];
            var b = data[(int)after];
            out_[i] = a + (b - a) * atPoint;
        }
        out_[fitCount - 1] = data[^1];
        return out_;
    }
}
