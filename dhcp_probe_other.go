//go:build !windows

package main

// dhcpProbe asks the network itself when no server is named, exactly as the Windows
// build does: a broadcast INFORM over every usable interface. With -s it measures
// that one server over a unicast socket.
func dhcpProbe(o dhcpOpts) (dhcpResult, error) {
	if o.ipv6 {
		return dhcpProbe6(o)
	}
	if o.server != "" {
		return dhcpProbeUDP(o)
	}
	res, err := dhcpBroadcastInform(o)
	if err == nil {
		return res, nil
	}
	// Last resort: a real DISCOVER on port 68, which needs root here.
	if res, uerr := dhcpProbeUDP(o); uerr == nil {
		return res, nil
	}
	return dhcpResult{}, err
}
