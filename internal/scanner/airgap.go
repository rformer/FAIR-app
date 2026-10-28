package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// InternalOnly enforces air-gapped TLS probing (F-015 T-37; design §11:
// "internal only"): every configured ingress endpoint ("host:port") must
// be, or resolve only to, private, loopback or link-local addresses. An
// endpoint that does not resolve is refused too, so a misconfiguration
// fails closed at startup instead of reaching outside.
func InternalOnly(ctx context.Context, endpoints []string, lookup func(ctx context.Context, host string) ([]net.IP, error)) error {
	var errs []error
	for _, ep := range endpoints {
		host, _, err := net.SplitHostPort(ep)
		if err != nil {
			errs = append(errs, fmt.Errorf("ingress endpoint %q: %w", ep, err))
			continue
		}
		ips := []net.IP{net.ParseIP(host)}
		if ips[0] == nil {
			if ips, err = lookup(ctx, host); err != nil {
				errs = append(errs, fmt.Errorf("ingress endpoint %q does not resolve: %w", ep, err))
				continue
			}
			if len(ips) == 0 {
				errs = append(errs, fmt.Errorf("ingress endpoint %q does not resolve to any address", ep))
				continue
			}
		}
		var public []string
		for _, ip := range ips {
			if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				public = append(public, ip.String())
			}
		}
		if len(public) > 0 {
			errs = append(errs, fmt.Errorf("ingress endpoint %q resolves to public addresses (%s); an air-gapped install probes internal endpoints only",
				ep, strings.Join(public, ", ")))
		}
	}
	return errors.Join(errs...)
}
