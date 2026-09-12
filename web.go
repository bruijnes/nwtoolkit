package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

func jsonWrite(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func qInt(r *http.Request, k string, def int) int {
	if v := r.URL.Query().Get(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func cmdWeb(addr string) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(webHTML))
	})

	// one ping measurement
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		ip, err := resolveIP(host, r.URL.Query().Get("v6") == "1")
		if err != nil {
			jsonWrite(w, map[string]any{"ok": false, "err": err.Error()})
			return
		}
		h, _ := icmpOpen()
		defer h.close()
		peer, rtt, status, err := h.echo(ip, 128, 3*time.Second, []byte("nwtoolkit"))
		res := map[string]any{"ip": ip.String()}
		if err != nil {
			res["ok"] = false
			res["err"] = err.Error()
		} else if status == ipSuccess {
			res["ok"] = true
			res["rtt_ms"] = float64(rtt.Microseconds()) / 1000
			res["from"] = peer.String()
		} else {
			res["ok"] = false
			res["err"] = ipStatusText(status)
		}
		jsonWrite(w, res)
	})

	// one DNS query
	mux.HandleFunc("/api/dns", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		server := serverAddr(q.Get("server"), q.Get("v6") == "1")
		name := q.Get("name")
		qt := q.Get("type")
		if qt == "" {
			qt = "A"
		}
		rtt, ans, err := doQuery(server, name, qtypeCode(qt), 3*time.Second)
		res := map[string]any{"rtt_ms": float64(rtt.Microseconds()) / 1000, "server": server}
		if err != nil {
			res["ok"] = false
			res["err"] = err.Error()
		} else {
			res["ok"] = true
			res["answers"] = ans
		}
		jsonWrite(w, res)
	})

	// one DHCP measurement
	mux.HandleFunc("/api/dhcp", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		o := dhcpOpts{server: q.Get("server"), iface: q.Get("iface"), timeout: 3 * time.Second, port: qInt(r, "port", 0), ipv6: q.Get("v6") == "1"}
		res, err := dhcpProbe(o)
		out := map[string]any{}
		if err != nil {
			out["ok"] = false
			out["err"] = err.Error()
		} else {
			out["ok"] = true
			out["rtt_ms"] = float64(res.rtt.Microseconds()) / 1000
			out["server"] = res.serverID.String()
			if len(res.servers) > 1 {
				all := make([]string, len(res.servers))
				for i, v := range res.servers {
					all[i] = v.String()
				}
				out["servers"] = all
			}
			if res.yiaddr != nil && !res.yiaddr.Equal(net.IPv4zero) {
				out["offer"] = res.yiaddr.String()
			}
			if res.info6 != "" {
				out["type"] = res.info6
			} else {
				out["type"] = map[byte]string{dhcpOffer: "OFFER", dhcpAck: "ACK"}[res.msgType]
			}
		}
		jsonWrite(w, out)
	})

	// full traceroute (one run)
	mux.HandleFunc("/api/traceroute", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		dst, err := resolveIP(host, r.URL.Query().Get("v6") == "1")
		if err != nil {
			jsonWrite(w, map[string]any{"ok": false, "err": err.Error()})
			return
		}
		h, _ := icmpOpen()
		defer h.close()
		hops := runTrace(h, dst, traceOpts{maxHops: qInt(r, "maxhops", 30), probes: qInt(r, "probes", 3), timeout: 2 * time.Second, resolve: r.URL.Query().Get("resolve") == "1"})
		var out []map[string]any
		for _, hp := range hops {
			m := map[string]any{"n": hp.n, "reached": hp.reached, "rtts": hp.rtts}
			if hp.ip != nil {
				m["ip"] = hp.ip.String()
				m["name"] = hp.name
			}
			out = append(out, m)
		}
		jsonWrite(w, map[string]any{"ok": true, "dst": dst.String(), "hops": out})
	})

	// LLDP neighbour (can take a while; the browser fetches with a long timeout)
	mux.HandleFunc("/api/lldp", func(w http.ResponseWriter, r *http.Request) {
		hint := r.URL.Query().Get("iface")
		wait := time.Duration(qInt(r, "wait", 35)) * time.Second
		nbs, dev, err := lldpOnce(hint, wait)
		if err != nil {
			jsonWrite(w, map[string]any{"ok": false, "err": err.Error()})
			return
		}
		var out []map[string]any
		for _, n := range nbs {
			out = append(out, map[string]any{
				"sysname": n.SysName, "port": n.PortID, "portdesc": n.PortDesc,
				"chassis": n.ChassisID, "vlan": n.VLAN, "mgmt": n.MgmtAddr,
				"caps": n.Caps, "ttl": n.TTL, "sysdesc": firstLine(n.SysDesc),
			})
		}
		jsonWrite(w, map[string]any{"ok": true, "device": dev, "neighbors": out})
	})

	// interface list for the LLDP tab
	mux.HandleFunc("/api/lldp/interfaces", func(w http.ResponseWriter, r *http.Request) {
		_, devs, _ := openLLDP("")
		jsonWrite(w, map[string]any{"interfaces": devs})
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		die("cannot start web UI on %s: %v", addr, err)
	}
	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	fmt.Printf("%s  web UI running at %s\n", col(cBold, "nwtoolkit"), col(cCyan, url))
	fmt.Println("Open that address in your browser. Ctrl+C to stop.")
	openBrowser(url)
	http.Serve(ln, mux)
}
