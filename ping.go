package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"
)

type pingOpts struct {
	host     string
	count    int // 0 = oneindig
	interval time.Duration
	timeout  time.Duration
	size     int
	ipv6     bool
}

func cmdPing(o pingOpts) {
	ip, err := resolveIP(o.host, o.ipv6)
	if err != nil {
		die("%v", err)
	}
	h, err := icmpOpen()
	if err != nil {
		die("kan ICMP niet openen: %v", err)
	}
	defer h.close()

	payload := make([]byte, o.size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}

	label := o.host
	if o.host != ip.String() {
		label = fmt.Sprintf("%s [%s]", o.host, ip)
	}
	fmt.Printf("PING %s met %d bytes data\n", label, o.size)

	var samples []float64
	lost := 0
	sent := 0

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	summary := func() {
		fmt.Printf("\n--- %s ping-statistiek ---\n", o.host)
		fmt.Println(computeStats(samples, lost))
	}

	tick := time.NewTicker(o.interval)
	defer tick.Stop()

	for {
		sent++
		peer, rtt, status, err := h.echo(ip, 128, o.timeout, payload)
		ms := float64(rtt.Microseconds()) / 1000
		switch {
		case err != nil:
			lost++
			fmt.Printf("  %s  %s\n", nowStamp(), col(cRed, "fout: "+err.Error()))
		case status == ipSuccess:
			samples = append(samples, ms)
			c := cGreen
			if ms > 100 {
				c = cYellow
			}
			fmt.Printf("  %s  antwoord van %-15s  tijd=%s  status=ok\n",
				nowStamp(), peer, col(c, fmt.Sprintf("%.2f ms", ms)))
		default:
			lost++
			if peer == nil || peer.IsUnspecified() {
				fmt.Printf("  %s  %s\n", nowStamp(), col(cRed, ipStatusText(status)))
			} else {
				fmt.Printf("  %s  %s van %s\n", nowStamp(), col(cRed, ipStatusText(status)), peer)
			}
		}

		if o.count > 0 && sent >= o.count {
			summary()
			return
		}
		select {
		case <-sig:
			summary()
			return
		case <-tick.C:
		}
	}
}
