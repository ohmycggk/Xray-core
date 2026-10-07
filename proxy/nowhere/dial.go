package nowhere

import (
	"context"
	stdnet "net"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// DialPolicy binds outbound source addresses per address family. It mirrors the
// Nowhere 2.2 reference (common::dial::DialPolicy dual-stack mode): dial4 pins
// the IPv4 source, dial6 the IPv6 source, and an unset or "auto" value leaves
// that family to the kernel. A zero value is the "auto" policy and preserves
// default dialing behavior.
type DialPolicy struct {
	v4 stdnet.IP
	v6 stdnet.IP
}

// Configured reports whether any source address is pinned. When it is not, the
// dialer keeps its default behavior.
func (p DialPolicy) Configured() bool {
	return p.v4 != nil || p.v6 != nil
}

// sourceFor returns the outbound source IP for a target of the given family, or
// nil to let the kernel choose. The dual-stack policy never restricts the
// target's family, so an unpinned family simply falls back to the kernel.
func (p DialPolicy) sourceFor(target stdnet.IP) stdnet.IP {
	if target.To4() != nil {
		return p.v4
	}
	return p.v6
}

// ParseDialPolicy validates the dual-stack dial4/dial6 parameters exactly as the
// reference DialPolicy::from_query does. Empty and "auto" select the kernel
// default; a literal must match the family it is given, and an IPv4-mapped IPv6
// literal is rejected for dial6.
func ParseDialPolicy(dial4, dial6 string) (DialPolicy, error) {
	var p DialPolicy
	if value := strings.TrimSpace(dial4); value != "" && value != "auto" {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return DialPolicy{}, errors.New("nowhere: dial4 must be auto or an IPv4 literal")
		}
		p.v4 = stdnet.IP(addr.AsSlice())
	}
	if value := strings.TrimSpace(dial6); value != "" && value != "auto" {
		addr, err := netip.ParseAddr(value)
		if err != nil || addr.Is4() || addr.Is4In6() {
			return DialPolicy{}, errors.New("nowhere: dial6 must be auto or an IPv6 literal")
		}
		p.v6 = stdnet.IP(addr.AsSlice())
	}
	return p, nil
}

// bindSource resolves address and returns the source IP the policy pins for the
// target's address family, or nil when that family is left to the kernel.
func (p DialPolicy) bindSource(ctx context.Context, address string) (stdnet.IP, error) {
	host, _, err := stdnet.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := stdnet.ParseIP(host); ip != nil {
		return p.sourceFor(ip), nil
	}
	addrs, err := stdnet.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("nowhere: no address resolved for ", host)
	}
	return p.sourceFor(addrs[0].IP), nil
}
