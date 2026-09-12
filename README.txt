nwtoolkit — network diagnostics (IPv4)
======================================

One Windows executable, no installation, no dependencies.
Double-click it for a window. Everything is scriptable from the command line
as well. Colours and charts work in Windows Terminal, PowerShell and cmd.

FEATURES
--------
1. Ping            — one-shot (4x) or continuous, with min/avg/max and loss %.
2. Traceroute      — one-shot, or a continuous monitor that tracks min/avg/max
                     latency and packet loss per hop in a live table.
3. DNS query       — look up a record against a specific or the system
                     resolver, with the response time in ms.
4. DNS speed test  — measure DNS response time, once or every 5 s continuously
                     with a live ASCII line chart.
5. DHCP speed test — measure how fast the DHCP server responds, once or
                     continuously with a chart. Always measures over a
                     broadcast to 255.255.255.255, so with no prior knowledge
                     of any server, the way a device behaves when it is first
                     plugged in. Every DHCP server on the segment answers; if
                     more than one does, they are all listed, and that is the
                     signal for a rogue server.
                     The request is a DHCP INFORM from a high port. Its answer
                     comes back on our own port and belongs to our outbound
                     traffic, so the firewall passes it and no Administrator is
                     needed. An INFORM also reserves no address, so repeated
                     measurement does not drain the address pool.
                     If that yields nothing, a real DISCOVER follows through
                     the built-in pktmon (Administrator), and after that a
                     plain socket on port 68.
                     Use -s <ip> to measure one specific server.
6. LLDP neighbour  — shows which switch and port you are connected to
                     (system name, port, VLAN, chassis MAC, mgmt address).

Plus a graphical web UI (nwtoolkit web) with real charts in the browser.

QUICK START
-----------
Double-click nwtoolkit.exe  -> opens a real Windows window (GUI) with tabs for
                            every feature and live charts.

Other ways to start:
  nwtoolkit gui    -> the same native window
  nwtoolkit web    -> the features in the browser instead of a window
  nwtoolkit menu   -> a text menu in the terminal

Tip: run as Administrator (right-click -> Run as administrator) for LLDP and
     for the DISCOVER fallback of the DHCP speed test.

Or from the command line:
  nwtoolkit ping 8.8.8.8 -t
  nwtoolkit trace switch.example.com -m
  nwtoolkit dns example.com -s 1.1.1.1 -type MX
  nwtoolkit dnsspeed example.com -s 1.1.1.1
  nwtoolkit dhcp -s 192.168.1.1
  nwtoolkit web

Full help:  nwtoolkit help

NOTES PER FEATURE
-----------------
Ping / Traceroute
  Uses the Windows ICMP API (IcmpSendEcho2). Works without Administrator.

DNS
  -s empty = system DNS (via GetNetworkParams). Otherwise -s <ip> or <ip:port>.

DHCP speed test
  With no -s the tool asks the network itself. It sends a DHCP INFORM to
  255.255.255.255 from an ephemeral port, over every usable interface at once,
  each from a socket bound to that interface's own address. Servers answer an
  INFORM on the port it came from, so the reply belongs to our own outbound
  flow: the firewall passes it, port 68 of the Windows DHCP Client service
  stays untouched, and no elevation is needed.

  If nothing answers, a real broadcast DISCOVER follows, captured with the
  built-in Packet Monitor. That path sees the frame below the firewall but
  requires Administrator. A plain socket on port 68 is the last resort.

  With -s <server-ip> the tool measures that one server with a unicast INFORM.

LLDP neighbour
  nwtoolkit lldp           -> shows the connected switch and port
  nwtoolkit lldp -l        -> list available interfaces
  nwtoolkit lldp -i Ethernet -w 40   -> pick an interface and wait time
  nwtoolkit lldp -m        -> keep monitoring (Windows: as Administrator)

  Windows cannot capture raw layer-2 frames in userland without a driver, so
  the tool always uses the BUILT-IN pktmon (Packet Monitor). That ships with
  Windows 10 and 11, needs no installation, and requires no Npcap or any other
  external driver. It does require Administrator, so run the exe elevated for
  LLDP.

Web UI
  nwtoolkit web            -> http://127.0.0.1:8733 (opens the browser)
  nwtoolkit web 0.0.0.0:8080  -> also reachable from other machines

If Windows SmartScreen blocks the exe (unsigned, downloaded from the internet):
  right-click -> Properties -> "Unblock", or in PowerShell:
  Unblock-File .\nwtoolkit.exe

Building it yourself (Go 1.24+):
  go build -ldflags "-s -w" -o nwtoolkit.exe .
