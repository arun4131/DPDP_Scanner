package piiscanner

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestPreprocessAndExtractKV(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		processed string
		want      []KeyValuePair
	}{
		{
			name:      "nested JSON with arrays and escaped strings",
			input:     `{"identity":{"pan":"ABCDE1234F"},"name":"John \"Johnny\" Doe","phones":["9876543210","9123456780"]}`,
			processed: `{"identity":{"pan":"ABCDE1234F"},"name":"John \"Johnny\" Doe","phones":["9876543210","9123456780"]}`,
			want: []KeyValuePair{
				{Key: "pan", Value: "ABCDE1234F"},
				{Key: "name", Value: `John "Johnny" Doe`},
				{Key: "phones", Value: "9876543210"},
				{Key: "phones", Value: "9123456780"},
			},
		},
		{
			name:      "query preserves encoded delimiter and duplicate keys",
			input:     `note=Tom%20%26%20Jerry&phone=9876543210&phone=9123456780`,
			processed: `note=Tom%20%26%20Jerry&phone=9876543210&phone=9123456780`,
			want: []KeyValuePair{
				{Key: "note", Value: "Tom & Jerry"},
				{Key: "phone", Value: "9876543210"},
				{Key: "phone", Value: "9123456780"},
			},
		},
		{
			name:      "full URL",
			input:     `https://example.com/api?pan=ABCDE1234F&aadhaar=123456789012`,
			processed: `https://example.com/api?pan=ABCDE1234F&aadhaar=123456789012`,
			want: []KeyValuePair{
				{Key: "aadhaar", Value: "123456789012"},
				{Key: "pan", Value: "ABCDE1234F"},
			},
		},
		{
			name:      "valid XML leaf nodes",
			input:     `<root><pan>ABCDE1234F</pan><phone>9876543210</phone></root>`,
			processed: `<root><pan>ABCDE1234F</pan><phone>9876543210</phone></root>`,
			want: []KeyValuePair{
				{Key: "pan", Value: "ABCDE1234F"},
				{Key: "phone", Value: "9876543210"},
			},
		},
		{
			name:      "malformed XML is rejected",
			input:     `<pan>ABCDE1234F</aadhaar>`,
			processed: `<pan>ABCDE1234F</aadhaar>`,
			want:      nil,
		},
		{
			name:      "URL encoded blob",
			input:     `pan%3DABCDE1234F%26aadhaar%3D123456789012`,
			processed: `pan=ABCDE1234F&aadhaar=123456789012`,
			want: []KeyValuePair{
				{Key: "aadhaar", Value: "123456789012"},
				{Key: "pan", Value: "ABCDE1234F"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processed, got := PreprocessAndExtractKV(tt.input)
			if processed != tt.processed {
				t.Fatalf("processed value = %q, want %q", processed, tt.processed)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pairs = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestPreprocessAndExtractKVBase64(t *testing.T) {
	jsonValue := `{"pan":"ABCDE1234F"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(jsonValue))

	processed, got := PreprocessAndExtractKV(encoded)
	if processed != jsonValue {
		t.Fatalf("processed value = %q, want %q", processed, jsonValue)
	}
	want := []KeyValuePair{{Key: "pan", Value: "ABCDE1234F"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pairs = %#v, want %#v", got, want)
	}
}

func TestPreprocessAndExtractKVDoesNotDecodeArbitraryBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("ordinary printable content"))
	processed, got := PreprocessAndExtractKV(encoded)
	if processed != encoded {
		t.Fatalf("arbitrary Base64 was decoded to %q", processed)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected pairs: %#v", got)
	}
}
