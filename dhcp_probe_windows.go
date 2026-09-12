//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
)

// dhcpProbe gebruikt op Windows uitsluitend boordmiddelen — geen Npcap, geen
// externe driver. In volgorde van voorkeur:
//
//  1. Unicast INFORM naar de DHCP-server die Windows zelf al kent (uit het
//     register). Loopt over een efemere poort, dus botst niet met de
//     DHCP-Clientservice die poort 68 bezit, en werkt zonder Administrator.
//  2. Broadcast DISCOVER, opgevangen met de ingebouwde Packet Monitor (pktmon).
//     Ziet het frame onder de firewall langs, maar vereist Administrator.
//  3. Broadcast DISCOVER over een gewone UDP-socket op poort 68. Werkt alleen als
//     de firewall het inkomende antwoord doorlaat.
func dhcpProbe(o dhcpOpts) (dhcpResult, error) {
	if o.ipv6 {
		return dhcpProbe6(o)
	}

	// De gebruiker gaf zelf een server op: rechtstreeks unicast INFORM.
	if o.server != "" && !o.discover {
		res, err := dhcpProbeUDP(o)
		if err == nil && res.method == "" {
			res.method = "INFORM"
		}
		return res, err
	}

	// Expliciete broadcast DISCOVER: doe alsof we dit netwerk niet kennen.
	if o.discover {
		return dhcpDiscoverBroadcast(o)
	}

	lease, lerr := leaseFor(o.iface, o.srcIP)

	// 1. Unicast INFORM naar de bekende server.
	if lerr == nil && lease.server != nil {
		u := o
		u.server = lease.server.String()
		u.port = 0 // efemere poort, poort 68 blijft van de Windows-clientservice
		if res, err := dhcpProbeUDP(u); err == nil {
			if res.serverID == nil {
				res.serverID = lease.server
			}
			res.method = "INFORM naar " + lease.server.String() + " (" + lease.label() + ")"
			return res, nil
		}
	}

	// 2. Broadcast DISCOVER via de ingebouwde pktmon.
	res, perr := dhcpProbePktmon(o)
	if perr == nil {
		return res, nil
	}

	// 3. Laatste poging: gewone UDP-broadcast op poort 68.
	if res, uerr := dhcpProbeUDP(o); uerr == nil {
		return res, nil
	} else if errors.Is(perr, errPktmonUnsupported) {
		perr = uerr
	}

	return dhcpResult{}, fmt.Errorf("%v%s", perr, leaseHint(lease, lerr))
}

// leaseHint vertelt wat Windows zelf al over de lease weet. Ook als geen enkele
// meting antwoord krijgt, is dat het antwoord op "welke DHCP-server bedient mij".
func leaseHint(l dhcpLease, err error) string {
	if err != nil || l.server == nil {
		return " — Windows kent zelf ook geen actieve DHCP-lease; start als Administrator zodat de ingebouwde pktmon gebruikt kan worden"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nWindows kent wél een lease op %s:", l.label())
	fmt.Fprintf(&b, "\n  DHCP-server   %s", l.server)
	if l.ip != nil {
		fmt.Fprintf(&b, "\n  Toegewezen IP %s", l.ip)
	}
	if l.gateway != nil {
		fmt.Fprintf(&b, "\n  Gateway       %s", l.gateway)
	}
	if len(l.dns) > 0 {
		names := make([]string, len(l.dns))
		for i, d := range l.dns {
			names[i] = d.String()
		}
		fmt.Fprintf(&b, "\n  DNS           %s", strings.Join(names, ", "))
	}
	if !l.obtained.IsZero() {
		fmt.Fprintf(&b, "\n  Lease vanaf   %s", l.obtained.Format("2006-01-02 15:04:05"))
	}
	if !l.expires.IsZero() {
		fmt.Fprintf(&b, "\n  Lease tot     %s", l.expires.Format("2006-01-02 15:04:05"))
	}
	b.WriteString("\nDe server antwoordt niet op een INFORM; start als Administrator voor de pktmon-meting.")
	return b.String()
}

// dhcpDiscoverBroadcast doet wat een kaal toestel doet dat net op een onbekend
// netwerk wordt aangesloten: een broadcast DISCOVER naar 255.255.255.255, zonder
// enige voorkennis van servers. Het antwoord komt terug op poort 68, die op
// Windows van de DHCP-Clientservice is en door de firewall wordt afgeschermd,
// dus de betrouwbare weg is de ingebouwde Packet Monitor. Die vereist
// Administrator; zonder die rechten wordt de gewone socket geprobeerd.
func dhcpDiscoverBroadcast(o dhcpOpts) (dhcpResult, error) {
	b := o
	b.server = "" // geen voorkennis
	if b.port == 0 {
		b.port = 68
	}

	elevated := isElevated()
	var perr error
	if elevated {
		res, err := dhcpProbePktmon(b)
		if err == nil {
			return res, nil
		}
		perr = err
	}

	// Zonder verhoogde rechten (of als pktmon faalde) blijft de gewone socket over.
	res, uerr := dhcpProbeUDP(b)
	if uerr == nil {
		if res.method == "" {
			res.method = "broadcast DISCOVER"
		}
		return res, nil
	}

	if !elevated {
		return dhcpResult{}, fmt.Errorf("broadcast DISCOVER kreeg geen antwoord: %v"+
			" — het OFFER komt binnen op poort 68, die van de Windows DHCP-Clientservice is"+
			" en door de firewall wordt afgeschermd. Start als Administrator; dan vangt de"+
			" ingebouwde pktmon het frame wél op", uerr)
	}
	if perr != nil && errors.Is(perr, errPktmonUnsupported) {
		return dhcpResult{}, fmt.Errorf("broadcast DISCOVER kreeg geen antwoord: %v — pktmon is op deze Windows-versie niet beschikbaar", uerr)
	}
	return dhcpResult{}, fmt.Errorf("broadcast DISCOVER kreeg geen antwoord: %v", perr)
}
