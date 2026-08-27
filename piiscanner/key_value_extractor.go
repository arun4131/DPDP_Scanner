package piiscanner

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type KeyValuePair struct {
	Key   string
	Value string
}

var (
	// These are fallbacks for malformed JSON-like blobs and simple key/value text.
	jsonQuotedKVRegex   = regexp.MustCompile(`"([^"\\]+)"\s*:\s*"([^"\\]+)"`)
	jsonUnquotedKVRegex = regexp.MustCompile(`"([^"\\]+)"\s*:\s*([0-9a-zA-Z._-]+)`)
	textKVRegex         = regexp.MustCompile(`(?i)\b([a-zA-Z0-9_-]{2,30})\s*[:=]\s*([^\s,;]{2,100})`)
)

type kvCollector struct {
	pairs []KeyValuePair
	seen  map[KeyValuePair]struct{}
}

func newKVCollector() *kvCollector {
	return &kvCollector{seen: make(map[KeyValuePair]struct{})}
}

func (c *kvCollector) add(key, value string) {
	pair := KeyValuePair{Key: strings.TrimSpace(key), Value: strings.TrimSpace(value)}
	if pair.Key == "" || pair.Value == "" {
		return
	}
	if _, exists := c.seen[pair]; exists {
		return
	}
	c.seen[pair] = struct{}{}
	c.pairs = append(c.pairs, pair)
}

// PreprocessAndExtractKV unwraps one URL or Base64 layer, then extracts fields
// from JSON, XML, query strings, or loose key/value text. Repeated keys are kept
// when their values differ.
func PreprocessAndExtractKV(text string) (string, []KeyValuePair) {
	processed := strings.TrimSpace(text)

	// Decode blobs that hide their separators behind URL encoding. Leave normal
	// query strings alone so an encoded '&' inside a value stays there.
	lower := strings.ToLower(processed)
	if strings.Contains(lower, "%3d") && !strings.Contains(processed, "=") {
		if decoded, err := url.QueryUnescape(processed); err == nil {
			processed = decoded
		}
	}

	if decoded, ok := decodeStructuredBase64(processed); ok {
		processed = decoded
	}

	collector := newKVCollector()
	trimmed := strings.TrimSpace(processed)

	jsonParsed := extractJSON(trimmed, collector)
	xmlParsed := false
	if !jsonParsed {
		xmlParsed = extractXML(trimmed, collector)
	}
	queryParsed := extractQuery(trimmed, collector)

	// Use the loose regex fallbacks only when the structured parsers fail. They
	// are deliberately permissive and can misread valid structured content.
	if !jsonParsed && !xmlParsed && !queryParsed {
		extractJSONFallback(trimmed, collector)
		if len(collector.pairs) == 0 {
			extractTextFallback(trimmed, collector)
		}
	}

	return processed, collector.pairs
}

func decodeStructuredBase64(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "<") {
		return "", false
	}

	clean := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, trimmed)
	if len(clean) < 8 {
		return "", false
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(clean)
		if err != nil || !utf8.Valid(decoded) || !mostlyPrintable(decoded) {
			continue
		}
		candidate := strings.TrimSpace(string(decoded))
		if looksStructured(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func mostlyPrintable(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	printable := 0
	for _, r := range string(value) {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return float64(printable)/float64(utf8.RuneCount(value)) >= 0.90
}

func looksStructured(value string) bool {
	if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") || strings.HasPrefix(value, "<") {
		return true
	}
	return strings.Contains(value, "=") && (strings.Contains(value, "&") || textKVRegex.MatchString(value))
}

func extractJSON(text string, collector *kvCollector) bool {
	if !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") {
		return false
	}

	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	// A second decoded value means there is trailing content after the JSON.
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return false
	}
	flattenJSON("", value, collector)
	return true
}

func flattenJSON(parentKey string, value any, collector *kvCollector) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			flattenJSON(key, typed[key], collector)
		}
	case []any:
		for _, item := range typed {
			flattenJSON(parentKey, item, collector)
		}
	case nil:
		return
	case string:
		collector.add(parentKey, typed)
	case json.Number:
		collector.add(parentKey, typed.String())
	case bool:
		collector.add(parentKey, fmt.Sprint(typed))
	}
}

func extractXML(text string, collector *kvCollector) bool {
	if !strings.HasPrefix(text, "<") {
		return false
	}

	type frame struct {
		name     string
		text     strings.Builder
		hasChild bool
	}

	decoder := xml.NewDecoder(strings.NewReader(text))
	stack := make([]*frame, 0)
	temporary := newKVCollector()
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		switch typed := token.(type) {
		case xml.StartElement:
			if len(stack) > 0 {
				stack[len(stack)-1].hasChild = true
			}
			stack = append(stack, &frame{name: typed.Name.Local})
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write([]byte(typed))
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].name != typed.Name.Local {
				return false
			}
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if !current.hasChild {
				temporary.add(current.name, current.text.String())
			}
		}
	}
	if len(stack) != 0 {
		return false
	}
	for _, pair := range temporary.pairs {
		collector.add(pair.Key, pair.Value)
	}
	return true
}

func extractQuery(text string, collector *kvCollector) bool {
	rawQuery := ""
	if parsed, err := url.Parse(text); err == nil && parsed.RawQuery != "" {
		rawQuery = parsed.RawQuery
	} else if strings.Contains(text, "=") && !strings.ContainsAny(text, "{}<>\n\r") {
		rawQuery = strings.TrimPrefix(text, "?")
	}
	if rawQuery == "" {
		return false
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) == 0 {
		return false
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range values[key] {
			collector.add(key, value)
		}
	}
	return len(collector.pairs) > 0
}

func extractJSONFallback(text string, collector *kvCollector) {
	for _, rx := range []*regexp.Regexp{jsonQuotedKVRegex, jsonUnquotedKVRegex} {
		for _, match := range rx.FindAllStringSubmatch(text, -1) {
			if len(match) >= 3 {
				collector.add(match[1], match[2])
			}
		}
	}
}

func extractTextFallback(text string, collector *kvCollector) {
	for _, match := range textKVRegex.FindAllStringSubmatch(text, -1) {
		if len(match) >= 3 {
			collector.add(match[1], strings.Trim(match[2], `"'{}[]()`))
		}
	}
}
