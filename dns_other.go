//go:build !windows

package main

// Op niet-Windows leest doQuery de resolver uit /etc/resolv.conf; deze fallback blijft leeg.
func systemDNS() string { return "" }
