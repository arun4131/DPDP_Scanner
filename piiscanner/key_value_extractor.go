package piiscanner

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

type KeyValuePair struct {
	Key   string
	Value string
}

var (
	jsonKVRegex = regexp.MustCompile(`"([^"]+)"\s*:\s*"?([^",{} \t\r\n]+)"?`)
	xmlKVRegex  = regexp.MustCompile(`<([a-zA-Z0-9_-]+)[^>]*>([^<]+)</[a-zA-Z0-9_-]+>`)
	textKVRegex = regexp.MustCompile(`(?i)\b([a-zA-Z0-9_-]{2,30})\s*[:=]\s*([^\s,;]{2,100})`)
)

// PreprocessAndExtractKV handles URL decoding, Base64 decoding, and key-value pair extraction
// from structured blobs (JSON, XML, Key-Value, URL params, and Base64 tokens).
func PreprocessAndExtractKV(text string) (string, []KeyValuePair) {
	processed := text

	// 1. Handle URL-encoded strings (e.g. pan%3DABCDE1234F%26aadhaar%3D123456789012)
	if strings.Contains(text, "%3D") || strings.Contains(text, "%3d") || strings.Contains(text, "%26") {
		if unescaped, err := url.QueryUnescape(text); err == nil {
			processed = unescaped
		}
	}

	// 2. Handle Base64-encoded strings (e.g. eyJwYW4iOiJBQkNERTEyMzRGIn0=)
	// Clean embedded newlines or spaces often injected by database formatting (e.g. \n or \r\n)
	cleanBase64 := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(text, "\n", ""), "\r", ""), " ", "")
	cleanBase64 = strings.TrimSpace(cleanBase64)
	if strings.HasPrefix(cleanBase64, "eyJ") || (len(cleanBase64) >= 16 && len(cleanBase64)%4 == 0) {
		if decodedBytes, err := base64.StdEncoding.DecodeString(cleanBase64); err == nil {
			decodedStr := string(decodedBytes)
			if len(decodedStr) > 0 && (strings.Contains(decodedStr, "{") || strings.Contains(decodedStr, ":") || strings.Contains(decodedStr, "=") || strings.Contains(decodedStr, "&")) {
				processed = decodedStr
			}
		}
	}

	kvMap := make(map[string]string)

	// Extract URL Query parameters (e.g. pan=ABCDE1234F&aadhaar=123456789012)
	if strings.Contains(processed, "=") && strings.Contains(processed, "&") {
		parts := strings.Split(processed, "&")
		for _, p := range parts {
			if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
				k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
				if k != "" && v != "" {
					kvMap[k] = v
				}
			}
		}
	}

	// Extract JSON key-value pairs
	if matches := jsonKVRegex.FindAllStringSubmatch(processed, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) >= 3 {
				k, v := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
				if k != "" && v != "" {
					kvMap[k] = v
				}
			}
		}
	}

	// Extract XML key-value pairs
	if matches := xmlKVRegex.FindAllStringSubmatch(processed, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) >= 3 {
				k, v := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
				if k != "" && v != "" {
					kvMap[k] = v
				}
			}
		}
	}

	// Extract Text key-value pairs (key: value or key=value)
	if matches := textKVRegex.FindAllStringSubmatch(processed, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) >= 3 {
				k, v := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
				if k != "" && v != "" {
					// Avoid overwriting clean values with un-split query string
					if _, exists := kvMap[k]; !exists {
						kvMap[k] = v
					}
				}
			}
		}
	}

	var kvList []KeyValuePair
	for k, v := range kvMap {
		kvList = append(kvList, KeyValuePair{Key: k, Value: v})
	}

	return processed, kvList
}
