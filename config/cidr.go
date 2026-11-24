package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// mergeCIDRLayers applies key from the .env file and then from the process
// environment, each only when its value is not blank after trimming.
func mergeCIDRLayers(dst *[]netip.Prefix, key string, fileVars map[string]string) error {
	if v, ok := fileVars[key]; ok && strings.TrimSpace(v) != "" {
		if err := mergeCIDRList(dst, key, v); err != nil {
			return err
		}
	}
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		if err := mergeCIDRList(dst, key, v); err != nil {
			return err
		}
	}
	return nil
}

// mergeCIDRList parses value with parseCIDRList and stores the result in dst.
// An empty (or all-whitespace) value stores nil, meaning no restriction.
func mergeCIDRList(dst *[]netip.Prefix, setting, value string) error {
	prefixes, err := parseCIDRList(setting, value)
	if err != nil {
		return err
	}
	*dst = prefixes
	return nil
}

// parseCIDRList parses a comma-separated list of CIDRs or single IP addresses.
// Whitespace around items is trimmed; a bare address becomes a /32 or /128.
// IPv4-mapped IPv6 items are converted to IPv4, because peer addresses are
// unmapped before matching and a mapped item would otherwise never match.
// Errors name the setting and quote the offending item.
func parseCIDRList(setting, value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	items := strings.Split(value, ",")
	out := make([]netip.Prefix, 0, len(items))
	for _, raw := range items {
		item := strings.TrimSpace(raw)
		p, err := parseCIDRItem(item)
		if err != nil {
			return nil, fmt.Errorf("invalid %s item %q: %v", setting, item, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseCIDRItem(item string) (netip.Prefix, error) {
	if item == "" {
		return netip.Prefix{}, fmt.Errorf("empty item")
	}
	if strings.Contains(item, "/") {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("not a CIDR")
		}
		addr := p.Addr()
		if addr.Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix shorter than /96")
			}
			p = netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(item)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an IP address or CIDR")
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("zoned addresses are not supported")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
