//go:build windows

package main

import (
	"errors"
	"fmt"
)

// dhcpProbe kiest op Windows — net als LLDP — de beste beschikbare methode:
//  1. Npcap (wpcap.dll): zelf zenden én op L2 ontvangen (realtime, nauwkeurigst).
//  2. pktmon (ingebouwd): zenden via socket, OFFER opvangen met Packet Monitor.
//  3. gewone UDP-socket (onbetrouwbaar; poort 68 is van de DHCP-Clientservice).
func dhcpProbe(o dhcpOpts) (dhcpResult, error) {
	if o.ipv6 {
		return dhcpProbe6(o)
	}

	res, err := dhcpProbeL2(o)
	if err == nil {
		return res, nil
	}
	if !errors.Is(err, errNoNpcap) {
		return dhcpResult{}, err // Npcap aanwezig maar het L2-pad faalde
	}

	// geen Npcap → pktmon-terugval (zoals LLDP)
	res, err = dhcpProbePktmon(o)
	if err == nil {
		return res, nil
	}
	if !errors.Is(err, errPktmonUnsupported) {
		return dhcpResult{}, err
	}

	// laatste redmiddel: gewone UDP-socket
	res, uerr := dhcpProbeUDP(o)
	if uerr != nil {
		return dhcpResult{}, fmt.Errorf("%v — installeer Npcap (https://npcap.com) of gebruik pktmon (Administrator) voor betrouwbare DHCP", uerr)
	}
	return res, nil
}
