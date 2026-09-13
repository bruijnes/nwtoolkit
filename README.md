# nwtoolkit

Network diagnostics for Windows in a single executable. No installation, no
dependencies. Double-click for a window, or drive everything from the command
line. Ping, traceroute, DNS, DHCP and LLDP, with live charts.

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

The result is one `nwtoolkit.exe` of roughly 33 MB: the .NET runtime and WPF are
bundled into it, which is what makes it run on a clean machine. The unused parts
of the runtime are trimmed away and runtime files the app never loads are left
out of the bundle; the publish settings and that list live in
`src/nwtoolkit/nwtoolkit.csproj`. The same command works from Windows, Linux or
macOS. The core library also builds and runs on Linux, which is handy for
testing the DNS and ping commands; LLDP and the window are Windows-only.

## Releases

The version number is set once, in `Directory.Build.props`. Pushing a tag
`vX.Y` makes CI build, test and attach the exe to a GitHub Release:

```
git tag -a v0.6 -m "nwtoolkit 0.6"
git push origin v0.6
```

Bump the version before tagging; the app compares its own version with the
latest release to show the update notice.

## License

MIT. See [LICENSE](LICENSE).
