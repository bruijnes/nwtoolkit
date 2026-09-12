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
	// De gebruiker gaf zelf een server op: gericht meten naar die ene server.
	if o.server != "" {
		res, err := dhcpProbeUDP(o)
		if err == nil && res.method == "" {
			res.method = "INFORM"
		}
		return res, err
	}
	// Anders altijd broadcast: het netwerk zelf vragen, zonder voorkennis.
	return dhcpDiscoverBroadcast(o)
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

	// 1. Broadcast INFORM vanaf een efemere poort. Werkt zonder verhoogde rechten
	//    en zonder pktmon, want het antwoord komt terug op onze eigen poort.
	res, informErr := dhcpBroadcastInform(b)
	if informErr == nil {
		return res, nil
	}

	// 2. Echte DISCOVER, opgevangen met de ingebouwde pktmon. Vereist Administrator.
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

	// 3. Laatste poging: DISCOVER over een gewone socket op poort 68.
	if res, err := dhcpProbeUDP(d); err == nil {
		if res.method == "" {
			res.method = "broadcast DISCOVER"
		}
		return res, nil
	}

	return dhcpResult{}, broadcastFailure(informErr, pktErr, elevated, o)
}

// broadcastFailure legt uit waarom geen van de broadcast-wegen iets opleverde.
func broadcastFailure(informErr, pktErr error, elevated bool, o dhcpOpts) error {
	var b strings.Builder
	b.WriteString("geen DHCP-server antwoordde op een broadcast")
	if informErr != nil {
		fmt.Fprintf(&b, "\n  INFORM naar 255.255.255.255: %v", informErr)
	}
	switch {
	case !elevated:
		b.WriteString("\n  DISCOVER via pktmon: overgeslagen, dat vereist Administrator")
	case pktErr != nil && errors.Is(pktErr, errPktmonUnsupported):
		b.WriteString("\n  DISCOVER via pktmon: pktmon is op deze Windows-versie niet beschikbaar")
	case pktErr != nil:
		fmt.Fprintf(&b, "\n  DISCOVER via pktmon: %v", pktErr)
	}
	if lease, err := leaseFor(o.iface, o.srcIP); err == nil && lease.server != nil {
		fmt.Fprintf(&b, "\n  Windows heeft wél een lease van %s op %s; die server negeert onze broadcast",
			lease.server, lease.label())
	}
	return errors.New(b.String())
}
