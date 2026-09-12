module nwtoolkit

go 1.24

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.33.0
	golang.org/x/mod => github.com/golang/mod v0.23.0
	golang.org/x/net => github.com/golang/net v0.35.0
	golang.org/x/sync => github.com/golang/sync v0.11.0
	golang.org/x/sys => github.com/golang/sys v0.30.0
	golang.org/x/term => github.com/golang/term v0.29.0
	golang.org/x/text => github.com/golang/text v0.22.0
	golang.org/x/tools => github.com/golang/tools v0.30.0
)

require (
	github.com/guptarohit/asciigraph v0.10.0
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	github.com/miekg/dns v1.1.62
	golang.org/x/net v0.35.0
	golang.org/x/sys v0.30.0
)

require (
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	gopkg.in/Knetic/govaluate.v3 v3.0.0-00010101000000-000000000000 // indirect
)

replace gopkg.in/Knetic/govaluate.v3 => github.com/Knetic/govaluate v3.0.0+incompatible
