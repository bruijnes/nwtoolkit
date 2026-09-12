//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	d "github.com/lxn/walk/declarative"
)

// writeCrash writes text to nwtoolkit-crash.log next to the exe, or in TEMP, and
// returns the path it used.
func writeCrash(msg string) string {
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	path := filepath.Join(dir, "nwtoolkit-crash.log")
	if os.WriteFile(path, []byte(msg), 0644) != nil {
		path = filepath.Join(os.TempDir(), "nwtoolkit-crash.log")
		os.WriteFile(path, []byte(msg), 0644)
	}
	return path
}

// crashLog catches a panic, logs the stack trace and shows an error message.
func crashLog() {
	if r := recover(); r != nil {
		msg := fmt.Sprintf("nwtoolkit %s crash %s\n%v\n\n%s\n",
			version, time.Now().Format("2006-01-02 15:04:05"), r, debug.Stack())
		path := writeCrash(msg)
		walk.MsgBox(nil, "nwtoolkit - startup error",
			fmt.Sprintf("%v\n\nDetails saved to:\n%s", r, path),
			walk.MsgBoxIconError)
	}
}

// guiFail logs a non-panic startup error, such as Create() failing, and shows it.
func guiFail(what string, err error) {
	msg := fmt.Sprintf("nwtoolkit %s startup error %s\n%s: %v\n",
		version, time.Now().Format("2006-01-02 15:04:05"), what, err)
	path := writeCrash(msg)
	walk.MsgBox(nil, "nwtoolkit - startup error",
		fmt.Sprintf("%s:\n%v\n\nDetails saved to:\n%s", what, err, path),
		walk.MsgBoxIconError)
}

var procSetWindowTheme = syscall.NewLazyDLL("uxtheme.dll").NewProc("SetWindowTheme")

// classicScrollbars strips the modern theme from a control so the classic,
// always-visible scrollbar with arrow buttons appears, instead of the Windows 11
// scrollbar that only reveals its arrows on hover.
func classicScrollbars(te *walk.TextEdit) {
	if te == nil {
		return
	}
	empty, _ := syscall.UTF16PtrFromString("")
	procSetWindowTheme.Call(uintptr(te.Handle()), uintptr(unsafe.Pointer(empty)), uintptr(unsafe.Pointer(empty)))
}

func mrg(n int) d.Margins { return d.Margins{Left: n, Top: n, Right: n, Bottom: n} }

const mitLicense = "MIT License\r\n\r\n" +
	"Copyright (c) 2026 Vincent Bruijnes\r\n\r\n" +
	"Permission is hereby granted, free of charge, to any person obtaining a copy\r\n" +
	"of this software and associated documentation files (the \"Software\"), to deal\r\n" +
	"in the Software without restriction, including without limitation the rights\r\n" +
	"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\r\n" +
	"copies of the Software, and to permit persons to whom the Software is\r\n" +
	"furnished to do so, subject to the following conditions:\r\n\r\n" +
	"The above copyright notice and this permission notice shall be included in all\r\n" +
	"copies or substantial portions of the Software.\r\n\r\n" +
	"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\r\n" +
	"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\r\n" +
	"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\r\n" +
	"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\r\n" +
	"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\r\n" +
	"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\r\n" +
	"SOFTWARE."

// ---- live chart data ----

type chartData struct {
	mu    sync.Mutex
	vals  []float64
	times []time.Time
	lost  int
	n     int
	unit  string
}

func (c *chartData) push(v float64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	if !ok {
		c.lost++
		return
	}
	c.vals = append(c.vals, v)
	c.times = append(c.times, time.Now())
	if len(c.vals) > 50000 { // generous history; the chart compresses to the available width
		c.vals = c.vals[len(c.vals)-50000:]
		c.times = c.times[len(c.times)-50000:]
	}
}

func (c *chartData) snapshot() ([]float64, []time.Time, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]float64(nil), c.vals...), append([]time.Time(nil), c.times...), c.lost, c.n
}

func (c *chartData) reset() {
	c.mu.Lock()
	c.vals, c.times, c.lost, c.n = nil, nil, 0, 0
	c.mu.Unlock()
}

var chartFont *walk.Font

func paintChart(cd *chartData, cw *walk.CustomWidget, canvas *walk.Canvas) error {
	if cw == nil {
		return nil
	}
	b := cw.ClientBoundsPixels() // the full widget size, not just the repaint area
	vals, times, _, _ := cd.snapshot()

	bgBrush, _ := walk.NewSolidColorBrush(walk.RGB(0xf0, 0xf0, 0xf0)) // same grey as the log box
	defer bgBrush.Dispose()
	canvas.FillRectanglePixels(bgBrush, b)

	border, _ := walk.NewCosmeticPen(walk.PenSolid, walk.RGB(0xc8, 0xcc, 0xd0))
	defer border.Dispose()
	canvas.DrawRectanglePixels(border, walk.Rectangle{X: b.X, Y: b.Y, Width: b.Width - 1, Height: b.Height - 1})

	grid, _ := walk.NewCosmeticPen(walk.PenSolid, walk.RGB(0xe6, 0xe8, 0xea))
	defer grid.Dispose()
	lineBrush, _ := walk.NewSolidColorBrush(walk.RGB(0x19, 0x4b, 0x4d))
	defer lineBrush.Dispose()
	linePen, _ := walk.NewGeometricPen(walk.PenSolid, 2, lineBrush)
	defer linePen.Dispose()

	padL, padT, padB, padR := 60, 14, 36, 14
	x0 := b.X + padL
	y0 := b.Y + padT
	plotW := b.Width - padL - padR
	plotH := b.Height - padT - padB
	if plotW < 40 || plotH < 30 {
		return nil
	}

	mn, mx := 0.0, 1.0
	if len(vals) > 0 {
		mn, mx = vals[0], vals[0]
		for _, v := range vals {
			if v < mn {
				mn = v
			}
			if v > mx {
				mx = v
			}
		}
	}
	if mx-mn < 1 {
		mx = mn + 1
	}
	rng := mx - mn
	mn -= rng * 0.1
	mx += rng * 0.1
	if mn < 0 {
		mn = 0
	}

	gx := func(i, n int) int {
		if n < 2 {
			return x0
		}
		return x0 + plotW*i/(n-1)
	}
	gy := func(v float64) int {
		return y0 + plotH - int(float64(plotH)*((v-mn)/(mx-mn)))
	}

	if chartFont != nil {
		for k := 0; k <= 4; k++ {
			vy := mn + (mx-mn)*float64(k)/4
			yy := gy(vy)
			canvas.DrawLinePixels(grid, walk.Point{X: x0, Y: yy}, walk.Point{X: x0 + plotW, Y: yy})
			canvas.DrawTextPixels(fmt.Sprintf("%.1f", vy), chartFont, walk.RGB(0x6a, 0x70, 0x78),
				walk.Rectangle{X: b.X + 6, Y: yy - 9, Width: padL - 14, Height: 18}, walk.TextRight|walk.TextSingleLine|walk.TextNoClip|walk.TextNoPrefix)
		}
	}

	n := len(vals)
	if n >= 2 && n <= plotW {
		// enough width: a plain line through every point
		for i := 1; i < n; i++ {
			canvas.DrawLinePixels(linePen,
				walk.Point{X: gx(i-1, n), Y: gy(vals[i-1])},
				walk.Point{X: gx(i, n), Y: gy(vals[i])})
		}
	} else if n > plotW {
		// more samples than pixels: compress per column into a min/max band plus an average line
		bandPen, _ := walk.NewCosmeticPen(walk.PenSolid, walk.RGB(0xbf, 0xd6, 0xd7))
		defer bandPen.Dispose()
		prevX, prevY, havePrev := 0, 0, false
		for cix := 0; cix < plotW; cix++ {
			lo := cix * n / plotW
			hi := (cix + 1) * n / plotW
			if hi <= lo {
				hi = lo + 1
			}
			if hi > n {
				hi = n
			}
			mnv, mxv, sum := vals[lo], vals[lo], 0.0
			for j := lo; j < hi; j++ {
				v := vals[j]
				if v < mnv {
					mnv = v
				}
				if v > mxv {
					mxv = v
				}
				sum += v
			}
			x := x0 + cix
			canvas.DrawLinePixels(bandPen, walk.Point{X: x, Y: gy(mxv)}, walk.Point{X: x, Y: gy(mnv)})
			ay := gy(sum / float64(hi-lo))
			if havePrev {
				canvas.DrawLinePixels(linePen, walk.Point{X: prevX, Y: prevY}, walk.Point{X: x, Y: ay})
			}
			prevX, prevY, havePrev = x, ay, true
		}
	}

	// x axis: time labels along the bottom, the clock time of each sample
	if chartFont != nil && n >= 2 {
		yLab := y0 + plotH + 5
		axisTick, _ := walk.NewCosmeticPen(walk.PenSolid, walk.RGB(0xc8, 0xcc, 0xd0))
		defer axisTick.Dispose()
		ticks := 5
		if plotW < 360 {
			ticks = 3
		}
		for t := 0; t <= ticks; t++ {
			i := (n - 1) * t / ticks
			x := gx(i, n)
			canvas.DrawLinePixels(axisTick, walk.Point{X: x, Y: y0 + plotH}, walk.Point{X: x, Y: y0 + plotH + 3})
			lbl := times[i].Format("15:04:05")
			bx := x - 30
			align := walk.TextCenter
			if t == 0 {
				bx = x
				align = walk.TextLeft
			} else if t == ticks {
				bx = x - 60
				align = walk.TextRight
			}
			canvas.DrawTextPixels(lbl, chartFont, walk.RGB(0x6a, 0x70, 0x78),
				walk.Rectangle{X: bx, Y: yLab, Width: 60, Height: 16}, align|walk.TextSingleLine|walk.TextNoClip|walk.TextNoPrefix)
		}
	}
	return nil
}

func statsText(vals []float64, lost, n int, unit string) string {
	if len(vals) == 0 {
		if n == 0 {
			return "Ready."
		}
		return fmt.Sprintf("samples: %d   errors: %d", n, lost)
	}
	mn, mx, sum := vals[0], vals[0], 0.0
	for _, v := range vals {
		sum += v
		if v < mn {
			mn = v
		}
		if v > mx {
			mx = v
		}
	}
	avg := sum / float64(len(vals))
	loss := float64(lost) * 100 / float64(n)
	return fmt.Sprintf("last %.2f %s     min %.2f     avg %.2f     max %.2f %s     loss %.0f%%     samples %d",
		vals[len(vals)-1], unit, mn, avg, mx, unit, loss, n)
}

// ---- per-tab job management ----

type job struct {
	stop    chan struct{}
	running bool
}

func (j *job) start() chan struct{} {
	j.halt()
	j.stop = make(chan struct{})
	j.running = true
	return j.stop
}
func (j *job) halt() {
	if j.running {
		close(j.stop)
		j.running = false
	}
}

func atof(s string, def float64) float64 {
	if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return v
	}
	return def
}

// runGUI shows the native Windows window.
func runGUI() {
	defer crashLog()
	kernel32.NewProc("FreeConsole").Call() // hide the console when double-clicked
	useColor = false
	chartFont, _ = walk.NewFont("Segoe UI", 8, 0) // fine and light; the dot now renders thanks to the text flags

	var mw *walk.MainWindow
	var status *walk.StatusBarItem
	var ipVer *walk.ComboBox

	var pHost, dName, dServer, dsName, dsServer *walk.LineEdit
	var pInt, dsInt, dhInt, dhTo, llWait *walk.LineEdit
	var dType, llIf, dhIf *walk.ComboBox
	var pChart, dsChart, dhChart *walk.CustomWidget
	var pStats, dsStats, dhStats *walk.Label
	var pLog, dOut, trOut, llOut, dhOut, aboutLic, aboutTxt *walk.TextEdit
	var trHost *walk.LineEdit
	var trMon *walk.CheckBox

	pData := &chartData{unit: "ms"}
	dsData := &chartData{unit: "ms"}
	dhData := &chartData{unit: "ms"}
	var pJob, dsJob, dhJob, trJob, llJob job

	syncUI := func(f func()) {
		if mw != nil {
			mw.Synchronize(f)
		}
	}
	setStatus := func(s string) {
		if status != nil {
			status.SetText(s)
		}
	}
	useV6 := func() bool { return ipVer != nil && ipVer.CurrentIndex() == 1 }

	startSpeed := func(j *job, cd *chartData, chart *walk.CustomWidget, stats *walk.Label, logv *walk.TextEdit,
		name string, interval time.Duration, measure func() (float64, string, error)) {
		stop := j.start()
		cd.reset()
		setStatus(name + " running…")
		go func() {
			for {
				v, info, err := measure()
				cd.push(v, err == nil)
				vals, _, lost, n := cd.snapshot()
				txt := statsText(vals, lost, n, cd.unit)
				syncUI(func() {
					stats.SetText(txt)
					setStatus(name + " running — " + txt)
					chart.Invalidate()
					if logv != nil {
						ts := time.Now().Format("15:04:05")
						if err != nil {
							logv.AppendText(fmt.Sprintf("%s  error: %s\r\n", ts, err.Error()))
						} else {
							logv.AppendText(fmt.Sprintf("%s  %.2f %s   %s\r\n", ts, v, cd.unit, info))
						}
					}
				})
				select {
				case <-stop:
					syncUI(func() { setStatus(name + " stopped.") })
					return
				case <-time.After(interval):
				}
			}
		}()
	}

	inputW := d.Size{Width: 190}

	pingPage := d.TabPage{
		Title:  "Ping",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(10), Spacing: 8},
		Children: []d.Widget{
			d.GroupBox{
				Title:  "Settings",
				Layout: d.HBox{Margins: mrg(10), Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "Host / IP:"},
					d.LineEdit{AssignTo: &pHost, Text: "1.1.1.1", MaxSize: inputW},
					d.Label{Text: "Interval (s):"},
					d.LineEdit{AssignTo: &pInt, Text: "1", MaxSize: d.Size{Width: 60}},
					d.PushButton{Text: "Start", MinSize: d.Size{Width: 90}, OnClicked: func() {
						ip, err := resolveIP(pHost.Text(), useV6())
						if err != nil {
							setStatus("error: " + err.Error())
							return
						}
						h, _ := icmpOpen()
						startSpeed(&pJob, pData, pChart, pStats, pLog, "Ping", dur(atof(pInt.Text(), 1)), func() (float64, string, error) {
							peer, rtt, st, err := h.echo(ip, 128, 2*time.Second, []byte("nwtoolkit"))
							if err != nil {
								return 0, "", err
							}
							if st != ipSuccess {
								return 0, "", fmt.Errorf("%s", ipStatusText(st))
							}
							return float64(rtt.Microseconds()) / 1000, "from " + peer.String(), nil
						})
					}},
					d.PushButton{Text: "Stop", MinSize: d.Size{Width: 90}, OnClicked: func() { pJob.halt() }},
					d.HSpacer{},
				},
			},
			d.GroupBox{
				Title:  "Response time (ms)",
				Layout: d.VBox{Margins: mrg(8), Spacing: 6},
				Children: []d.Widget{
					d.Label{AssignTo: &pStats, Text: "Ready."},
					d.CustomWidget{AssignTo: &pChart, MinSize: d.Size{Height: 120}, StretchFactor: 1, InvalidatesOnResize: true, Paint: func(c *walk.Canvas, _ walk.Rectangle) error { return paintChart(pData, pChart, c) }},
				},
			},
			d.GroupBox{
				Title:    "Log",
				Layout:   d.VBox{Margins: mrg(8)},
				MaxSize:  d.Size{Height: 140},
				MinSize:  d.Size{Height: 70},
				Children: []d.Widget{d.TextEdit{AssignTo: &pLog, ReadOnly: true, VScroll: true, Font: d.Font{Family: "Consolas", PointSize: 9}}},
			},
		},
	}

	tracePage := d.TabPage{
		Title:  "Traceroute",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(10), Spacing: 8},
		Children: []d.Widget{
			d.GroupBox{
				Title:  "Settings",
				Layout: d.HBox{Margins: mrg(10), Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "Host / IP:"},
					d.LineEdit{AssignTo: &trHost, Text: "example.com", MaxSize: d.Size{Width: 220}},
					d.CheckBox{AssignTo: &trMon, Text: "monitor continuously"},
					d.PushButton{Text: "Start", MinSize: d.Size{Width: 90}, OnClicked: func() {
						dst, err := resolveIP(trHost.Text(), useV6())
						if err != nil {
							trOut.SetText("error: " + err.Error())
							return
						}
						host := trHost.Text()
						mon := trMon.Checked()
						h, _ := icmpOpen()
						stop := trJob.start()
						setStatus("Traceroute running…")
						go func() {
							for {
								hops := runTrace(h, dst, traceOpts{maxHops: 30, probes: 3, timeout: 2 * time.Second, resolve: true})
								txt := traceText(host, dst.String(), hops)
								syncUI(func() { trOut.SetText(txt); setStatus("Traceroute done.") })
								if !mon {
									return
								}
								select {
								case <-stop:
									return
								case <-time.After(3 * time.Second):
								}
							}
						}()
					}},
					d.PushButton{Text: "Stop", MinSize: d.Size{Width: 90}, OnClicked: func() { trJob.halt() }},
					d.HSpacer{},
				},
			},
			d.GroupBox{
				Title:    "Route (times in ms)",
				Layout:   d.VBox{Margins: mrg(8)},
				Children: []d.Widget{d.TextEdit{AssignTo: &trOut, ReadOnly: true, VScroll: true, Font: d.Font{Family: "Consolas", PointSize: 9}}},
			},
		},
	}

	dnsPage := d.TabPage{
		Title:  "DNS query",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(10), Spacing: 8},
		Children: []d.Widget{
			d.GroupBox{
				Title:  "Settings",
				Layout: d.HBox{Margins: mrg(10), Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "Name:"},
					d.LineEdit{AssignTo: &dName, Text: "example.com", MaxSize: inputW},
					d.Label{Text: "Server:"},
					d.LineEdit{AssignTo: &dServer, CueBanner: "empty = system", MaxSize: d.Size{Width: 140}},
					d.Label{Text: "Type:"},
					d.ComboBox{AssignTo: &dType, Value: "A", Model: []string{"A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"}},
					d.PushButton{Text: "Query", MinSize: d.Size{Width: 90}, OnClicked: func() {
						server := serverAddr(dServer.Text(), useV6())
						qt := qtypeCode(fmt.Sprintf("%v", dType.Text()))
						name := dName.Text()
						dOut.SetText("working…")
						setStatus("DNS query…")
						go func() {
							rtt, ans, err := doQuery(server, name, qt, 3*time.Second)
							var sb strings.Builder
							fmt.Fprintf(&sb, "Server:        %s\r\nResponse time: %.2f ms\r\n\r\n", server, float64(rtt.Microseconds())/1000)
							if err != nil {
								fmt.Fprintf(&sb, "Error: %s\r\n", err.Error())
							} else if len(ans) == 0 {
								sb.WriteString("(no records)\r\n")
							} else {
								for _, a := range ans {
									sb.WriteString(a + "\r\n")
								}
							}
							txt := sb.String()
							syncUI(func() { dOut.SetText(txt); setStatus("DNS query done.") })
						}()
					}},
					d.HSpacer{},
				},
			},
			d.GroupBox{
				Title:    "Answer",
				Layout:   d.VBox{Margins: mrg(8)},
				Children: []d.Widget{d.TextEdit{AssignTo: &dOut, ReadOnly: true, VScroll: true, Font: d.Font{Family: "Consolas", PointSize: 9}}},
			},
		},
	}

	dnsSpeedPage := d.TabPage{
		Title:  "DNS speed test",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(10), Spacing: 8},
		Children: []d.Widget{
			d.GroupBox{
				Title:  "Settings",
				Layout: d.HBox{Margins: mrg(10), Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "Name:"},
					d.LineEdit{AssignTo: &dsName, Text: "example.com", MaxSize: inputW},
					d.Label{Text: "Server:"},
					d.LineEdit{AssignTo: &dsServer, CueBanner: "empty = system", MaxSize: d.Size{Width: 140}},
					d.Label{Text: "Interval (s):"},
					d.LineEdit{AssignTo: &dsInt, Text: "5", MaxSize: d.Size{Width: 60}},
					d.PushButton{Text: "Start", MinSize: d.Size{Width: 90}, OnClicked: func() {
						server := serverAddr(dsServer.Text(), useV6())
						name := dsName.Text()
						startSpeed(&dsJob, dsData, dsChart, dsStats, nil, "DNS speed test", dur(atof(dsInt.Text(), 5)), func() (float64, string, error) {
							rtt, ans, err := doQuery(server, name, qtypeCode("HINFO"), 3*time.Second)
							info := ""
							if len(ans) > 0 {
								info = ans[0]
							}
							return float64(rtt.Microseconds()) / 1000, info, err
						})
					}},
					d.PushButton{Text: "Stop", MinSize: d.Size{Width: 90}, OnClicked: func() { dsJob.halt() }},
					d.HSpacer{},
				},
			},
			d.GroupBox{
				Title:  "Response time (ms)",
				Layout: d.VBox{Margins: mrg(8), Spacing: 6},
				Children: []d.Widget{
					d.Label{AssignTo: &dsStats, Text: "Ready."},
					d.CustomWidget{AssignTo: &dsChart, MinSize: d.Size{Height: 140}, StretchFactor: 1, InvalidatesOnResize: true, Paint: func(c *walk.Canvas, _ walk.Rectangle) error { return paintChart(dsData, dsChart, c) }},
				},
			},
		},
	}

	dhcpPage := d.TabPage{
		Title:  "DHCP speed test",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(10), Spacing: 8},
		Children: []d.Widget{
			d.GroupBox{
				Title:  "Settings",
				Layout: d.HBox{Margins: mrg(10), Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "Interface:"},
					d.ComboBox{AssignTo: &dhIf, Editable: true, MaxSize: d.Size{Width: 220}},
					d.Label{Text: "Interval (s):"},
					d.LineEdit{AssignTo: &dhInt, Text: "5", MaxSize: d.Size{Width: 50}},
					d.Label{Text: "Timeout (s):"},
					d.LineEdit{AssignTo: &dhTo, Text: "8", MaxSize: d.Size{Width: 50}},
					d.PushButton{Text: "Start", MinSize: d.Size{Width: 90}, OnClicked: func() {
						sel := strings.TrimSpace(dhIf.Text())
						var srcIP net.IP
						name := ""
						if sel != "" && sel != "(automatic)" {
							name = sel
							if i := strings.LastIndex(sel, "("); i >= 0 {
								srcIP = net.ParseIP(strings.Trim(sel[i+1:], "() "))
							}
						}
						to := dur(atof(dhTo.Text(), 8))
						if to <= 0 {
							to = 8 * time.Second
						}
						o := dhcpOpts{iface: name, srcIP: srcIP, timeout: to, ipv6: useV6()}
						startSpeed(&dhJob, dhData, dhChart, dhStats, dhOut, "DHCP speed test", dur(atof(dhInt.Text(), 5)), func() (float64, string, error) {
							res, err := dhcpProbe(o)
							if err != nil {
								return 0, "", err
							}
							mt := "OFFER"
							if res.msgType == dhcpAck {
								mt = "ACK"
							}
							info := mt + " from " + res.serverID.String()
							if res.method != "" {
								info += "  [" + res.method + "]"
							}
							if sum := res.serverSummary(); sum != "" {
								info += "  ⚠ " + sum
							}
							return float64(res.rtt.Microseconds()) / 1000, info, nil
						})
					}},
					d.PushButton{Text: "Stop", MinSize: d.Size{Width: 90}, OnClicked: func() { dhJob.halt() }},
					d.HSpacer{},
				},
			},
			d.GroupBox{
				Title:  "Response time (ms)",
				Layout: d.VBox{Margins: mrg(8), Spacing: 6},
				Children: []d.Widget{
					d.Label{AssignTo: &dhStats, Text: "Ready."},
					d.CustomWidget{AssignTo: &dhChart, MinSize: d.Size{Height: 130}, StretchFactor: 1, InvalidatesOnResize: true, Paint: func(c *walk.Canvas, _ walk.Rectangle) error { return paintChart(dhData, dhChart, c) }},
					d.TextEdit{AssignTo: &dhOut, ReadOnly: true, MinSize: d.Size{Height: 90}, Font: d.Font{Family: "Consolas", PointSize: 9}},
				},
			},
		},
	}

	lldpPage := d.TabPage{
		Title:  "LLDP neighbour",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(10), Spacing: 8},
		Children: []d.Widget{
			d.GroupBox{
				Title:  "Settings",
				Layout: d.HBox{Margins: mrg(10), Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "Interface:"},
					d.ComboBox{AssignTo: &llIf, Editable: true, MaxSize: d.Size{Width: 260}},
					d.Label{Text: "Wait (s):"},
					d.LineEdit{AssignTo: &llWait, Text: "35", MaxSize: d.Size{Width: 60}},
					d.PushButton{Text: "Find neighbour", MinSize: d.Size{Width: 110}, OnClicked: func() {
						hint := llIf.Text()
						wait := dur(atof(llWait.Text(), 35))
						llOut.SetText("Searching for LLDP frames… this can take up to ~30 s.\r\n")
						setStatus("Searching for LLDP…")
						llJob.start()
						go func() {
							nbs, dev, err := lldpOnce(hint, wait)
							syncUI(func() {
								if err != nil {
									llOut.SetText("error: " + err.Error())
									setStatus("LLDP error.")
									return
								}
								if len(nbs) == 0 {
									llOut.SetText("No LLDP neighbour seen on " + dev + ".\r\nLLDP may be disabled, or it is an unmanaged switch.")
									setStatus("LLDP: no neighbour.")
									return
								}
								var sb strings.Builder
								for _, n := range nbs {
									sb.WriteString(neighborText(n))
									sb.WriteString("\r\n")
								}
								llOut.SetText(sb.String())
								setStatus("LLDP done.")
							})
						}()
					}},
					d.HSpacer{},
				},
			},
			d.GroupBox{
				Title:  "Connected switch/port",
				Layout: d.VBox{Margins: mrg(8), Spacing: 6},
				Children: []d.Widget{
					d.TextEdit{AssignTo: &llOut, ReadOnly: true, VScroll: true, Font: d.Font{Family: "Consolas", PointSize: 9}},
				},
			},
		},
	}

	overPage := d.TabPage{
		Title:  "About",
		Font:   d.Font{Family: "Segoe UI", PointSize: 9},
		Layout: d.VBox{Margins: mrg(18), Spacing: 6},
		Children: []d.Widget{
			d.Label{Text: "nwtoolkit " + version, Font: d.Font{Family: "Segoe UI", PointSize: 15, Bold: true}},
			d.VSpacer{Size: 4},
			d.TextEdit{
				AssignTo: &aboutTxt,
				ReadOnly: true,
				MaxSize:  d.Size{Height: 130},
				MinSize:  d.Size{Height: 110},
				Font:     d.Font{Family: "Segoe UI", PointSize: 9},
				Text: "Network diagnostic tool for IPv4, IPv6 and LLDP.  Made by vibe coding using Anthropic's Claude*.\r\n\r\n" +
					"Software is licensed under the MIT license. If you have any suggestions, bug fixes or want to get in touch visit: https://github.com/bruijnes/.\r\n\r\n" +
					"* Claude is a trademark of Anthropic, PBC.",
			},
			d.VSpacer{Size: 6},
			d.Label{Text: "MIT license", Font: d.Font{Family: "Segoe UI", PointSize: 9, Bold: true}},
			d.TextEdit{
				AssignTo:      &aboutLic,
				ReadOnly:      true,
				VScroll:       true,
				Font:          d.Font{Family: "Consolas", PointSize: 9},
				Text:          mitLicense,
				StretchFactor: 1,
			},
		},
	}

	if err := (d.MainWindow{
		AssignTo: &mw,
		Title:    "nwtoolkit " + version + " — network diagnostics (IPv4)",
		MinSize:  d.Size{Width: 520, Height: 380},
		Size:     d.Size{Width: 1000, Height: 700},
		Layout:   d.VBox{Margins: mrg(0)},
		Children: []d.Widget{
			d.Composite{
				Layout: d.HBox{Margins: d.Margins{Left: 10, Top: 6, Right: 10, Bottom: 0}, Spacing: 8},
				Children: []d.Widget{
					d.Label{Text: "IP version:"},
					d.ComboBox{AssignTo: &ipVer, Value: "IPv4", Model: []string{"IPv4", "IPv6"}, MaxSize: d.Size{Width: 90}},
					d.HSpacer{},
				},
			},
			d.TabWidget{Font: d.Font{Family: "Segoe UI", PointSize: 10}, Pages: []d.TabPage{pingPage, tracePage, dnsPage, dnsSpeedPage, dhcpPage, lldpPage, overPage}},
		},
		StatusBarItems: []d.StatusBarItem{{AssignTo: &status, Text: "Ready.", Width: 1200}},
	}).Create(); err != nil {
		guiFail("could not create GUI window", err)
		return
	}

	// classic, always-visible scrollbars on the text boxes
	classicScrollbars(pLog)
	classicScrollbars(trOut)
	classicScrollbars(dOut)
	classicScrollbars(llOut)
	classicScrollbars(dhOut)
	classicScrollbars(aboutLic)

	go func() {
		if _, devs, _ := openLLDP(""); len(devs) > 0 {
			syncUI(func() { llIf.SetModel(devs) })
		}
	}()
	// DHCP interface list from the real NICs
	{
		items := []string{"(automatic)"}
		for _, ic := range usableIPv4Ifaces() {
			items = append(items, fmt.Sprintf("%s  (%s)", ic.name, ic.ip))
		}
		dhIf.SetModel(items)
	}

	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		pJob.halt()
		dsJob.halt()
		dhJob.halt()
		trJob.halt()
		llJob.halt()
	})

	mw.Run()
}

// ---- text formatting for the GUI ----

func traceText(host, dst string, hops []hopResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "traceroute to %s (%s)\r\n\r\n", host, dst)
	fmt.Fprintf(&sb, "%-3s  %-36s  %s\r\n", "hop", "adres", "rtt (ms)")
	fmt.Fprintf(&sb, "%s\r\n", strings.Repeat("-", 62))
	for _, hr := range hops {
		addr := "* * *"
		if hr.ip != nil {
			addr = hr.ip.String()
			if hr.name != "" {
				addr = hr.name + " (" + hr.ip.String() + ")"
			}
		}
		var rtts []string
		for _, r := range hr.rtts {
			if r < 0 {
				rtts = append(rtts, "*")
			} else {
				rtts = append(rtts, fmt.Sprintf("%.2f", r))
			}
		}
		mark := ""
		if hr.reached {
			mark = "   <= target"
		}
		fmt.Fprintf(&sb, "%-3d  %-36s  %s%s\r\n", hr.n, addr, strings.Join(rtts, "  "), mark)
	}
	return sb.String()
}

func neighborText(n *lldpNeighbor) string {
	var sb strings.Builder
	add := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&sb, "  %-16s %s\r\n", k+":", v)
		}
	}
	sb.WriteString("LLDP neighbour (connected device):\r\n")
	add("System name", n.SysName)
	add("Port", n.PortID)
	add("Port descr.", n.PortDesc)
	if n.VLAN > 0 {
		add("VLAN", strconv.Itoa(n.VLAN))
	}
	add("Chassis ID", n.ChassisID)
	add("Mgmt address", n.MgmtAddr)
	add("Capabilities", n.Caps)
	if n.TTL > 0 {
		add("TTL", strconv.Itoa(n.TTL)+" s")
	}
	if n.SysDesc != "" {
		add("System info", firstLine(n.SysDesc))
	}
	return sb.String()
}
