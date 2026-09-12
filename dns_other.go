//go:build !windows

package main

// On non-Windows, doQuery reads the resolver from /etc/resolv.conf; this fallback stays empty.
func systemDNS() string { return "" }
