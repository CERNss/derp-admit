package derp

import (
	"encoding/json"
	"fmt"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// ParseRequest decodes a derper admit-callback body and returns the request
// together with the canonical node-key string that identifies the device.
func ParseRequest(body []byte) (tailcfg.DERPAdmitClientRequest, string, error) {
	var req tailcfg.DERPAdmitClientRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, "", fmt.Errorf("decode DERPAdmitClientRequest: %w", err)
	}
	if req.NodePublic.IsZero() {
		return req, "", fmt.Errorf("node key missing from DERP request")
	}
	return req, req.NodePublic.String(), nil
}

// NormalizeNodeKey validates a caller-supplied node key and returns it in the
// exact canonical form ParseRequest derives from derper, so device identities
// stored at registration match the identities seen at verify time.
func NormalizeNodeKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty node key")
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(raw)); err != nil {
		return "", fmt.Errorf("invalid node key: %w", err)
	}
	if k.IsZero() {
		return "", fmt.Errorf("zero node key")
	}
	return k.String(), nil
}

func BuildResponse(allow bool, denyReason string) map[string]any {
	resp := map[string]any{
		"Allow": allow,
	}
	if !allow && denyReason != "" {
		resp["DenyReason"] = denyReason
	}
	return resp
}
