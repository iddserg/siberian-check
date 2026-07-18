package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// resolveIPs returns the sorted, de-duplicated set of IPv4/IPv6 addresses for
// domain (both A and AAAA records).
func resolveIPs(ctx context.Context, domain string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", domain, err)
	}

	seen := make(map[string]net.IP)
	for _, a := range addrs {
		seen[a.IP.String()] = a.IP
	}

	ips := make([]net.IP, 0, len(seen))
	for _, ip := range seen {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].String() < ips[j].String() })
	return ips, nil
}

// parseIPs parses a comma-separated list of literal IP addresses.
func parseIPs(raw string) ([]net.IP, error) {
	parts := strings.Split(raw, ",")
	out := make([]net.IP, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %q", p)
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IP address provided")
	}
	return out, nil
}
