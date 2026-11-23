package server

import "testing"

func TestIPRateLimiterGroupsIPv6By64(t *testing.T) {
	limiter := newIPRateLimiter(0.01, 1)

	// First IPv6 address consumes the single token for 2001:db8:abcd:1::/64.
	if !limiter.Allow("2001:db8:abcd:1::1") {
		t.Fatalf("first request from /64 should be allowed")
	}

	// A different host address in the same /64 shares that bucket and is denied.
	if limiter.Allow("2001:db8:abcd:1:ffff:ffff:ffff:ffff") {
		t.Fatalf("second address in same /64 should share bucket and be denied")
	}

	// A different /64 prefix has its own independent bucket.
	if !limiter.Allow("2001:db8:abcd:2::1") {
		t.Fatalf("address in different /64 should have its own bucket")
	}

	// An IPv4 address also has its own independent bucket.
	if !limiter.Allow("192.0.2.1") {
		t.Fatalf("IPv4 address should have its own bucket")
	}
}

func TestIPRateLimiterIPv4PerAddress(t *testing.T) {
	limiter := newIPRateLimiter(0.01, 1)

	if !limiter.Allow("192.0.2.1") {
		t.Fatalf("first request from 192.0.2.1 should be allowed")
	}
	if limiter.Allow("192.0.2.1") {
		t.Fatalf("second request from 192.0.2.1 should be denied")
	}
	// IPv4-mapped IPv6 form maps to the same IPv4 bucket.
	if limiter.Allow("::ffff:192.0.2.1") {
		t.Fatalf("IPv4-mapped form of 192.0.2.1 should share bucket and be denied")
	}
	// A different IPv4 address in the same subnet has its own bucket.
	if !limiter.Allow("192.0.2.2") {
		t.Fatalf("192.0.2.2 should have its own bucket")
	}
}
