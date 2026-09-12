# nwtoolkit

Network diagnostics for Windows in a single executable. No installation, no
dependencies. Double-click for a window, or drive everything from the command
line. Ping, traceroute, DNS, DHCP and LLDP, with live charts.

![build](https://github.com/bruijnes/nwtoolkit/actions/workflows/build.yml/badge.svg)

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

A graphical web UI (`nwtoolkit web`) offers the same features with charts in the
browser.

## Quick start

Double-click `nwtoolkit.exe` to open a native Windows window with a tab and live
chart for every feature.

Other ways to start:

```
nwtoolkit gui     native Windows window
nwtoolkit web     the features in the browser
nwtoolkit menu    an interactive text menu
```

Or from the command line:

```
nwtoolkit ping 8.8.8.8 -t
nwtoolkit trace switch.example.com -m
nwtoolkit dns example.com -s 1.1.1.1 -type MX
nwtoolkit dnsspeed example.com -s 1.1.1.1
nwtoolkit dhcp
nwtoolkit web
```

Run `nwtoolkit help` for the full list of commands and flags.

## Notes per feature

**Ping and traceroute** use the Windows ICMP API and work without Administrator.

**DNS** uses the system resolver when no server is given, otherwise `-s <ip>` or
`-s <ip:port>`.

**DHCP speed test.** With no `-s` the tool asks the network itself. It sends a
DHCP INFORM to `255.255.255.255` from an ephemeral port, over every usable
interface at once, each bound to that interface's own address. Servers answer an
INFORM on the port it came from, so the reply belongs to our own outbound flow:
the firewall passes it, port 68 of the Windows DHCP Client service stays
untouched, and no elevation is needed. If more than one server answers, they are
all listed, which is the signal for a rogue DHCP server. If nothing answers, a
real broadcast DISCOVER follows, captured with the built-in Packet Monitor, which
requires Administrator. With `-s <ip>` the tool measures one specific server.

**LLDP.** Windows cannot capture raw layer-2 frames in userland without a driver,
so the tool uses the built-in Packet Monitor (pktmon). That ships with Windows 10
and 11 and needs no Npcap or other external driver, but it does require
Administrator. Run the exe elevated for LLDP.

**Web UI.** `nwtoolkit web` serves on `http://127.0.0.1:8733` and opens the
browser. `nwtoolkit web 0.0.0.0:8080` makes it reachable from other machines.

## SmartScreen

The executable is unsigned, so Windows SmartScreen may warn on first run. If you
downloaded it, clear the block: right-click, Properties, Unblock, or in
PowerShell `Unblock-File .\nwtoolkit.exe`.

## Build from source

Requires Go 1.24 or newer.

```
go build -ldflags "-s -w" -o nwtoolkit.exe .
```

Cross-compiling from Linux or macOS works too:

```
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o nwtoolkit.exe .
```

The manifest and version metadata are embedded through
`resource_windows_amd64.syso`, generated from `versioninfo.json` with
[goversioninfo](https://github.com/josephspurrier/goversioninfo). Regenerate it
after changing `versioninfo.json`:

```
go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
goversioninfo -64 -o resource_windows_amd64.syso versioninfo.json
```

## License

MIT. See [LICENSE](LICENSE).
