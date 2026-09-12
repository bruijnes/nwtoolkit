using System.Net;
using static Nwtoolkit.Util;

namespace Nwtoolkit;

public sealed class PingOpts
{
    public string Host = "";
    public int Count = 4; // 0 = endless
    public TimeSpan Interval = TimeSpan.FromSeconds(1);
    public TimeSpan Timeout = TimeSpan.FromSeconds(2);
    public int Size = 32;
    public bool IPv6;
}

public static class PingCmd
{
    public static byte[] Payload(int size)
    {
        var payload = new byte[Math.Max(0, size)];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)('a' + i % 26);
        return payload;
    }

    public static void Run(PingOpts o)
    {
        IPAddress ip;
        try { ip = ResolveIP(o.Host, o.IPv6); }
        catch (Exception e) { Die(e.Message); return; }

        using var echo = new Echo();
        var payload = Payload(o.Size);

        var label = o.Host;
        if (o.Host != ip.ToString()) label = $"{o.Host} [{ip}]";
        Console.WriteLine($"PING {label} with {o.Size} bytes of data");

        var samples = new List<double>();
        var lost = 0;
        var sent = 0;
        using var ctrlC = new CtrlC();

        void Summary()
        {
            Console.WriteLine($"\n--- {o.Host} ping statistics ---");
            Console.WriteLine(Stats.Compute(samples, lost));
        }

        while (true)
        {
            sent++;
            var r = echo.Send(ip, 128, o.Timeout, payload);
            var ms = r.Ms;
            if (r.Error != null)
            {
                lost++;
                Console.WriteLine($"  {NowStamp()}  {Col(CRed, "error: " + r.Error)}");
            }
            else if (r.Status == System.Net.NetworkInformation.IPStatus.Success)
            {
                samples.Add(ms);
                var c = ms > 100 ? CYellow : CGreen;
                Console.WriteLine($"  {NowStamp()}  reply from {r.Peer,-15}  time={Col(c, ms.F(2) + " ms")}  status=ok");
            }
            else
            {
                lost++;
                if (r.NoAnswer)
                    Console.WriteLine($"  {NowStamp()}  {Col(CRed, Echo.StatusText(r.Status))}");
                else
                    Console.WriteLine($"  {NowStamp()}  {Col(CRed, Echo.StatusText(r.Status))} from {r.Peer}");
            }

            if (o.Count > 0 && sent >= o.Count)
            {
                Summary();
                return;
            }
            if (ctrlC.Wait(o.Interval))
            {
                Summary();
                return;
            }
        }
    }
}
