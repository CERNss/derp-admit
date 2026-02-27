package derp

import (
	"encoding/json"
	"fmt"
	"strings"

	"tailscale.com/tailcfg"
)

func ParseRequest(body []byte) (tailcfg.DERPAdmitClientRequest, string, error) {
	var req tailcfg.DERPAdmitClientRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, "", fmt.Errorf("decode DERPAdmitClientRequest: %w", err)
	}

	nodeKey, err := extractNodeKey(req)
	if err != nil {
		return req, "", err
	}
	return req, nodeKey, nil
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

func extractNodeKey(req tailcfg.DERPAdmitClientRequest) (string, error) {
	marshaled, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("re-encode DERP request: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(marshaled, &raw); err != nil {
		return "", fmt.Errorf("re-decode DERP request: %w", err)
	}

	for _, key := range []string{"nodekey", "node_key", "nodepublic", "node_public", "publickey"} {
		if value, ok := findStringCaseInsensitive(raw, key); ok && value != "" {
			return value, nil
		}
	}

	return "", fmt.Errorf("node key not found in DERP request")
}

func findStringCaseInsensitive(v any, target string) (string, bool) {
	switch typed := v.(type) {
	case map[string]any:
		for k, nested := range typed {
			if strings.EqualFold(k, target) {
				if str, ok := nested.(string); ok {
					return strings.TrimSpace(str), true
				}
			}
			if value, ok := findStringCaseInsensitive(nested, target); ok {
				return value, true
			}
		}
	case []any:
		for _, nested := range typed {
			if value, ok := findStringCaseInsensitive(nested, target); ok {
				return value, true
			}
		}
	}
	return "", false
}
