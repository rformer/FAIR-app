package gateway

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Session network binding (F-001 T-20; design §5.8): the client's address
// comes from the trusted proxy header only when the request arrives from a
// trusted proxy; a session is on its network while the address stays in the
// recorded prefix and, with an ASN database, the same ASN.

// Network configures the client address and the binding check.
type Network struct {
	// Header is the trusted proxy header: "X-Forwarded-For", "X-Real-IP"
	// or "" (use the connection's address).
	Header string
	// Trusted are the proxies (the ingress) whose header is believed.
	Trusted []netip.Prefix
	// V4Bits and V6Bits are the prefix sizes of a network (default 24, 64).
	V4Bits, V6Bits int
	// ASN maps addresses to autonomous systems; nil checks prefixes only
	// (air-gapped installs without the database).
	ASN *ASNDB
}

func (n Network) bits() (int, int) {
	v4, v6 := n.V4Bits, n.V6Bits
	if v4 == 0 {
		v4 = 24
	}
	if v6 == 0 {
		v6 = 64
	}
	return v4, v6
}

func (n Network) trusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range n.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP is the request's client address. A header from a hop that is
// not a trusted proxy is ignored; in X-Forwarded-For the client is the
// right-most address that is not a trusted proxy.
func (n Network) ClientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	remote = remote.Unmap()
	if n.Header == "" || !n.trusted(remote) {
		return remote
	}
	switch http.CanonicalHeaderKey(n.Header) {
	case "X-Real-Ip":
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(n.Header))); err == nil {
			return a.Unmap()
		}
		return remote
	default: // X-Forwarded-For
		var hops []string
		for _, v := range r.Header.Values(n.Header) {
			hops = append(hops, strings.Split(v, ",")...)
		}
		client := remote
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return client // garbage: stop at the last address a trusted hop vouched for
			}
			client = a.Unmap()
			if !n.trusted(client) {
				return client
			}
		}
		return client
	}
}

// SameNetwork reports whether now is on the network recorded at login.
func (n Network) SameNetwork(recorded, now netip.Addr) bool {
	recorded, now = recorded.Unmap(), now.Unmap()
	if recorded.Is4() != now.Is4() {
		return false
	}
	v4, v6 := n.bits()
	bits := v6
	if recorded.Is4() {
		bits = v4
	}
	p, err := recorded.Prefix(bits)
	if err != nil || !p.Contains(now) {
		return false
	}
	if n.ASN == nil {
		return true
	}
	a, aok := n.ASN.Lookup(recorded)
	b, bok := n.ASN.Lookup(now)
	return aok == bok && a == b
}

// ASNDB maps address ranges to AS numbers (iptoasn.com's ip2asn TSV
// files, public domain).
type ASNDB struct {
	ranges []asnRange // sorted by start, not overlapping
}

type asnRange struct {
	start, end netip.Addr
	asn        int
}

// ASN files in a directory.
var asnFiles = []string{"ip2asn-v4.tsv", "ip2asn-v6.tsv"}

// LoadASNDB reads ip2asn-v4.tsv and ip2asn-v6.tsv (or .tsv.gz) from dir;
// at least one must exist. Lines are "start\tend\tasn\tcountry\tname";
// AS 0 (not routed) is skipped.
func LoadASNDB(dir string) (*ASNDB, error) {
	db := &ASNDB{}
	found := 0
	for _, name := range asnFiles {
		for _, f := range []string{name, name + ".gz"} {
			p := filepath.Join(dir, f)
			if _, err := os.Stat(p); err != nil {
				continue
			}
			if err := db.load(p); err != nil {
				return nil, err
			}
			found++
			break
		}
	}
	if found == 0 {
		return nil, fmt.Errorf("gateway: no ip2asn-v4.tsv or ip2asn-v6.tsv in %s", dir)
	}
	slices.SortFunc(db.ranges, func(a, b asnRange) int { return a.start.Compare(b.start) })
	for i := 1; i < len(db.ranges); i++ {
		if db.ranges[i].start.Compare(db.ranges[i-1].end) <= 0 {
			return nil, fmt.Errorf("gateway: overlapping ASN ranges at %s", db.ranges[i].start)
		}
	}
	return db, nil
}

func (db *ASNDB) load(path string) error {
	f, err := os.Open(path) // #nosec G304 -- the operator's ASN database directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var rd io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gateway: %s: %w", path, err)
		}
		defer func() { _ = gz.Close() }()
		rd = gz
	}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 3 {
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			return fmt.Errorf("gateway: %s:%d: want start, end, asn", path, line)
		}
		start, err1 := netip.ParseAddr(fields[0])
		end, err2 := netip.ParseAddr(fields[1])
		asn, err3 := strconv.Atoi(fields[2])
		if err := errors.Join(err1, err2, err3); err != nil {
			return fmt.Errorf("gateway: %s:%d: %w", path, line, err)
		}
		start, end = start.Unmap(), end.Unmap()
		if start.Is4() != end.Is4() || end.Less(start) {
			return fmt.Errorf("gateway: %s:%d: bad range", path, line)
		}
		if asn > 0 {
			db.ranges = append(db.ranges, asnRange{start, end, asn})
		}
	}
	return sc.Err()
}

// Lookup returns the AS number of a, if any.
func (db *ASNDB) Lookup(a netip.Addr) (int, bool) {
	a = a.Unmap()
	i, _ := slices.BinarySearchFunc(db.ranges, a, func(r asnRange, t netip.Addr) int { return r.start.Compare(t) })
	// ranges[i-1] is the last range starting at or before a (or i itself on an exact match).
	if i < len(db.ranges) && db.ranges[i].start == a {
		return db.ranges[i].asn, true
	}
	if i > 0 && db.ranges[i-1].start.Is4() == a.Is4() && db.ranges[i-1].end.Compare(a) >= 0 {
		return db.ranges[i-1].asn, true
	}
	return 0, false
}

// Len is the number of ranges loaded.
func (db *ASNDB) Len() int { return len(db.ranges) }
