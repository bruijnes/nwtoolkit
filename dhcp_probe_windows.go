//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
)

// dhcpProbe uses nothing but what Windows ships with — no Npcap, no external
// driver. In order of preference:
//
//  1. Broadcast INFORM from an ephemeral port. Does not collide with the DHCP
//     Client service that owns port 68, and works without Administrator.
//  2. Broadcast DISCOVER captured with the built-in Packet Monitor (pktmon).
//     Sees the frame below the firewall, but requires Administrator.
//  3. Broadcast DISCOVER over an ordinary UDP socket on port 68. Only works if
//     the firewall passes the incoming answer.
func dhcpProbe(o dhcpOpts) (dhcpResult, error) {
	if o.ipv6 {
		return dhcpProbe6(o)
	}
	// The user named a server: measure that one specifically.
	if o.server != "" {
		res, err := dhcpProbeUDP(o)
		if err == nil && res.method == "" {
			res.method = "INFORM"
		}
		return res, err
	}
	// Otherwise always broadcast: ask the network itself, with no prior knowledge.
	return dhcpDiscoverBroadcast(o)
}

// dhcpDiscoverBroadcast does what a bare device does when it is first plugged into
// an unknown network: it asks the segment itself, with no prior knowledge of any
// server. The INFORM path comes first because it needs no elevation; a real
// DISCOVER is answered on port 68, which on Windows belongs to the DHCP Client
// service and is shielded by the firewall, so that path needs Packet Monitor and
// Administrator rights.
func dhcpDiscoverBroadcast(o dhcpOpts) (dhcpResult, error) {
	b := o
	b.server = "" // no prior knowledge

	// 1. Broadcast INFORM from an ephemeral port. Works without elevation and
	//    without pktmon, because the answer comes back on our own port.
	res, informErr := dhcpBroadcastInform(b)
	if informErr == nil {
		return res, nil
	}

	// 2. A real DISCOVER, captured with the built-in pktmon. Requires Administrator.
	d := b
	if d.port == 0 {
		d.port = 68
	}
	elevated := isElevated()
	var pktErr error
	if elevated {
		if res, err := dhcpProbePktmon(d); err == nil {
			return res, nil
		} else {
			pktErr = err
		}
	}

	// 3. Last resort: DISCOVER over an ordinary socket on port 68.
	if res, err := dhcpProbeUDP(d); err == nil {
		if res.method == "" {
			res.method = "broadcast DISCOVER"
		}
		return res, nil
	}

	return dhcpResult{}, broadcastFailure(informErr, pktErr, elevated, o)
}

// broadcastFailure explains why none of the broadcast paths produced anything.
func broadcastFailure(informErr, pktErr error, elevated bool, o dhcpOpts) error {
	var b strings.Builder
	b.WriteString("no DHCP server answered a broadcast")
	if informErr != nil {
		fmt.Fprintf(&b, "\n  INFORM to 255.255.255.255: %v", informErr)
	}
	switch {
	case !elevated:
		b.WriteString("\n  DISCOVER via pktmon: skipped, that requires Administrator")
	case pktErr != nil && errors.Is(pktErr, errPktmonUnsupported):
		b.WriteString("\n  DISCOVER via pktmon: pktmon is not available on this Windows version")
	case pktErr != nil:
		fmt.Fprintf(&b, "\n  DISCOVER via pktmon: %v", pktErr)
	}
	if lease, err := leaseFor(o.iface, o.srcIP); err == nil && lease.server != nil {
		fmt.Fprintf(&b, "\n  Windows does hold a lease from %s on %s; that server ignores our broadcast",
			lease.server, lease.label())
	}
	return errors.New(b.String())
}
