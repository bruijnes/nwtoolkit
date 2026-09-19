# nwtoolkit

Network diagnostics for Windows in a single executable. No installation, no
dependencies. Double-click for a window, or drive everything from the command
line. Ping, traceroute, DNS, DHCP, LLDP and packet capture, with live charts.

![build](https://github.com/bruijnes/nwtoolkit/actions/workflows/build.yml/badge.svg)

Download the latest `nwtoolkit.exe` from the
[releases page](https://github.com/bruijnes/nwtoolkit/releases/latest).

## Features

- **Ping** — one-shot or continuous, with min/avg/max and loss percentage.
- **Traceroute** — one-shot, or a continuous monitor tracking min/avg/max latency
  and packet loss per hop.
- **DNS query** — look up a record against a specific or the system resolver,
  with the response time.
- **DNS speed test** — measure response time, once or continuously with a live
  chart.
- **DHCP speed test** — measure how fast the DHCP server responds. By default it
  broadcasts to the network with no prior knowledge of any server, the way a
  device behaves when first plugged in, and lists every server that answers.
- **LLDP neighbour** — show which switch and port you are connected to: system
  name, port, VLAN, chassis MAC and management address.
- **Packet capture** — a live tcpdump on the adapter you pick, one line per
  packet, with filters on address, port and protocol — each per direction or
  both — and an optional `.pcapng` file to open in Wireshark.

The window follows the Windows light or dark app mode, and tells you when a
newer release is available on GitHub.

## Quick start

Double-click `nwtoolkit.exe` to open a window with a tab and live chart for
every feature.

Other ways to start:

```
nwtoolkit gui     the window
nwtoolkit menu    an interactive text menu
```

Or from the command line:

```
nwtoolkit ping 8.8.8.8 -t
nwtoolkit trace switch.example.com -m
nwtoolkit dns example.com -s 1.1.1.1 -type MX
nwtoolkit dnsspeed example.com -s 1.1.1.1
nwtoolkit dhcp
nwtoolkit lldp
nwtoolkit tcpdump -i Ethernet -port 53 -c 20
```

Run `nwtoolkit help` for the full list of commands and flags.

## Notes per feature

**Ping and traceroute** use the Windows ICMP API and work without Administrator.
With `-n` (on by default in the window) the responding addresses are shown with
their DNS names; every address is looked up once and cached.

**DNS** uses the system resolver when no server is given, otherwise `-s <ip>`,
`-s <ip:port>` or `-s <name>`.

**DHCP speed test.** With no `-s` the tool asks the network itself. It sends a
DHCP INFORM to `255.255.255.255` from an ephemeral port, over every usable
interface at once, each bound to that interface's own address. Servers answer an
INFORM on the port it came from, so the reply belongs to our own outbound flow:
the firewall passes it, port 68 of the Windows DHCP Client service stays
untouched, and no elevation is needed. If more than one server answers, they are
all listed, which is the signal for a rogue DHCP server. If nothing answers, a
real broadcast DISCOVER follows, captured with the built-in Packet Monitor, which
requires Administrator. With `-s <ip>` the tool measures one specific server.
Each measurement waits at most five seconds.

**LLDP.** Windows cannot capture raw layer-2 frames without a driver, so the
tool uses the built-in Packet Monitor (pktmon). That ships with Windows 10 and
11 and needs no Npcap or other external driver, but it does require
Administrator. The window offers to restart elevated; on the command line, run
the exe as Administrator.

**Packet capture** binds a raw socket to the chosen adapter and puts it in
SIO_RCVALL mode, the one promiscuous capture Windows offers without a driver. It
therefore needs Administrator, and it delivers IP packets without the Ethernet
frame around them: TCP, UDP, ICMP and anything else over IPv4 or IPv6, but no
ARP and no VLAN tags. Use the LLDP command when layer 2 is what you need.

With no `-i` the adapter of the default route is used — the one the machine
would send over — so a capture is one command:

```
nwtoolkit tcpdump -c 5
nwtoolkit  capturing on Ethernet (192.168.1.10), IPv4, no link layer
14:52:07.418293 IP 192.168.1.10.51234 > 8.8.8.8.53: UDP (domain), length 40
14:52:07.431180 IP 8.8.8.8.53 > 192.168.1.10.51234: UDP (domain), length 56
14:52:07.433902 IP 192.168.1.10.51235 > 93.184.216.34.443: TCP (https) [S], seq 2847362, win 64240, length 0
14:52:07.449117 IP 93.184.216.34.443 > 192.168.1.10.51235: TCP (https) [S.], seq 118292, ack 2847363, win 65535, length 0
14:52:07.462004 IP 192.168.1.10 > 8.8.8.8: ICMP echo request, id 1, seq 4, length 32
```

Every flag is optional and they combine with AND:

```
-i <iface>   adapter by name, description or IP        default: the default route
-l           list the adapters that can be captured on
-c <n>       stop after n packets                      -d <s>  stop after s seconds
-host <ip>   address on either side                    -port <n>   port on either side
-src <ip>    address the packet came from              -sport <n>  port it came from
-dst <ip>    address the packet is going to            -dport <n>  port it is going to
-proto <p>   tcp, udp or icmp (icmp covers ICMPv6)
-w <file>    also write a .pcapng to open in Wireshark
-6           capture IPv6 instead of IPv4
```

The direction-specific filters are what tell a request apart from the answer to
it, and an address and a port on the same side pin down a single flow:

```
nwtoolkit tcpdump -l                                 list the adapters
nwtoolkit tcpdump -proto udp -port 53 -c 20          the next 20 DNS packets
nwtoolkit tcpdump -src 192.168.1.10 -dport 443       what this host sends to HTTPS
nwtoolkit tcpdump -dst 10.0.0.1 -d 30 -w dump.pcapng half a minute towards a host
```

A name given to `-host`, `-src` or `-dst` is resolved once, to every address it
has, so a site answering from a second address keeps matching. In the window the
dropdown beside each filter field — `src / dst`, `src`, `dst` — makes the same
choice as those flags, and the header line above the packets always spells the
filter back out.

## SmartScreen

The executable is unsigned, so Windows SmartScreen may warn on first run. If you
downloaded it, clear the block: right-click, Properties, Unblock, or in
PowerShell `Unblock-File .\nwtoolkit.exe`.

## Build from source

Requires the .NET 10 SDK. The solution has three projects:

```
src/nwtoolkit.Core    all network logic, the command line and the text menu (cross-platform)
src/nwtoolkit         the Windows executable: command line plus the WPF window (Fluent theme)
tests/nwtoolkit.Tests unit tests (xunit)
```

Build, test and publish a self-contained single-file exe that needs no .NET
installation on the target machine:

```
dotnet test tests/nwtoolkit.Tests
dotnet publish src/nwtoolkit -c Release -o dist
```

The result is one `nwtoolkit.exe` of roughly 35 MB: the .NET runtime and WPF are
bundled into it, which is what makes it run on a clean machine. The unused parts
of the runtime are trimmed away and runtime files the app never loads are left
out of the bundle; the publish settings and that list live in
`src/nwtoolkit/nwtoolkit.csproj`. The same command works from Windows, Linux or
macOS. The core library also builds and runs on Linux, which is handy for
testing the DNS and ping commands; LLDP, the packet capture and the window are
Windows-only.

## Releases

The version number is set once, in `Directory.Build.props`. Pushing a tag
`vX.Y` makes CI build, test and attach the exe to a GitHub Release:

```
git tag -a v0.7 -m "nwtoolkit 0.7"
git push origin v0.7
```

Bump the version before tagging; the app compares its own version with the
latest release to show the update notice.

## License

MIT. See [LICENSE](LICENSE).
