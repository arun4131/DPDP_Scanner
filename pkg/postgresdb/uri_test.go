package postgresdb

import (
	"strings"
	"testing"
)

func TestParseConnectionURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    Postgres
		wantErr string
	}{
		{
			name: "basic postgres URI with sslmode disable",
			uri:  "postgres://user:pass@localhost:5432/mydb?sslmode=disable",
			want: Postgres{
				Host:      "localhost",
				Port:      "5432",
				User:      "user",
				Password:  "pass",
				DBName:    "mydb",
				SSLmode:   "disable",
				PingCheck: true,
			},
		},
		{
			name: "postgresql scheme defaults port when omitted",
			uri:  "postgresql://alice@db.example.com/analytics",
			want: Postgres{
				Host:      "db.example.com",
				Port:      "5432",
				User:      "alice",
				DBName:    "analytics",
				PingCheck: true,
			},
		},
		{
			name: "verify-full with cert query params",
			uri:  "postgres://ro:s3cret@prod.example.com:5433/prod_db?sslmode=verify-full&sslrootcert=/certs/root.crt&sslcert=/certs/client.crt&sslkey=/certs/client.key",
			want: Postgres{
				Host:        "prod.example.com",
				Port:        "5433",
				User:        "ro",
				Password:    "s3cret",
				DBName:      "prod_db",
				SSLmode:     "verify-full",
				SSLcert:     "/certs/client.crt",
				SSLkey:      "/certs/client.key",
				SSLrootcert: "/certs/root.crt",
				PingCheck:   true,
			},
		},
		{
			name: "IPv6 host",
			uri:  "postgres://u:p@[::1]:5432/testdb?sslmode=disable",
			want: Postgres{
				Host:      "::1",
				Port:      "5432",
				User:      "u",
				Password:  "p",
				DBName:    "testdb",
				SSLmode:   "disable",
				PingCheck: true,
			},
		},
		{
			name:    "missing scheme rejected",
			uri:     "localhost:5432/mydb",
			wantErr: "unsupported connection URI scheme",
		},
		{
			name:    "mysql scheme rejected",
			uri:     "mysql://user:pass@localhost:3306/mydb",
			wantErr: "unsupported connection URI scheme",
		},
		{
			name:    "missing database name",
			uri:     "postgres://user:pass@localhost:5432/",
			wantErr: "missing a database name",
		},
		{
			name:    "missing host",
			uri:     "postgres:///mydb",
			wantErr: "missing a host",
		},
		{
			name:    "invalid sslmode",
			uri:     "postgres://user:pass@localhost:5432/mydb?sslmode=bogus",
			wantErr: "invalid PostgreSQL sslmode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseConnectionURI(tt.uri)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIsConnectionURI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"postgres://user:pass@host/db", true},
		{"postgresql://user:pass@host/db", true},
		{"  Postgres://user:pass@host/db", true},
		{"host=localhost dbname=mydb", false},
		{"", false},
		{"http://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsConnectionURI(tt.input); got != tt.want {
				t.Fatalf("IsConnectionURI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatHostPort(t *testing.T) {
	tests := []struct {
		host, port, want string
	}{
		{"localhost", "5432", "localhost:5432"},
		{"localhost", "", "localhost:5432"},
		{"::1", "5432", "[::1]:5432"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := FormatHostPort(tt.host, tt.port); got != tt.want {
				t.Fatalf("FormatHostPort(%q, %q) = %q, want %q", tt.host, tt.port, got, tt.want)
			}
		})
	}
}
