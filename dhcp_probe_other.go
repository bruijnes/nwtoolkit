//go:build !windows

package main

// dhcpProbe gebruikt op niet-Windows platforms de UDP-socketmethode.
func dhcpProbe(o dhcpOpts) (dhcpResult, error) {
	if o.ipv6 {
		return dhcpProbe6(o)
	}
	return dhcpProbeUDP(o)
}
