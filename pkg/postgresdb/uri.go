package postgresdb

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseConnectionURI parses a PostgreSQL URI of the form:
//
//	postgres://user:pass@host:5432/dbname?sslmode=disable
//	postgresql://user:pass@host:5432/dbname
//
// Query parameters sslmode, sslcert, sslkey, and sslrootcert are mapped onto
// the returned Postgres config. Other query parameters are ignored.
func ParseConnectionURI(uri string) (Postgres, error) {
	var conf Postgres

	u, err := url.Parse(uri)
	if err != nil {
		return conf, fmt.Errorf("invalid PostgreSQL connection URI: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
	default:
		return conf, fmt.Errorf("unsupported connection URI scheme %q (expected postgres:// or postgresql://)", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return conf, fmt.Errorf("connection URI is missing a host")
	}
	conf.Host = host

	port := u.Port()
	if port == "" {
		port = "5432"
	}
	conf.Port = port

	if u.User != nil {
		conf.User = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			conf.Password = pass
		}
	}

	dbname := strings.TrimPrefix(u.Path, "/")
	dbname = strings.TrimSuffix(dbname, "/")
	if dbname == "" {
		return conf, fmt.Errorf("connection URI is missing a database name")
	}
	// Path may be URL-escaped (e.g. my%20db).
	if decoded, err := url.PathUnescape(dbname); err == nil {
		dbname = decoded
	}
	conf.DBName = dbname

	q := u.Query()
	conf.SSLmode = q.Get("sslmode")
	conf.SSLcert = q.Get("sslcert")
	conf.SSLkey = q.Get("sslkey")
	conf.SSLrootcert = q.Get("sslrootcert")
	conf.PingCheck = true

	if err := validateSSLMode(conf.SSLmode); err != nil {
		return Postgres{}, err
	}

	return conf, nil
}

// IsConnectionURI reports whether s looks like a PostgreSQL connection URI.
func IsConnectionURI(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://")
}

// FormatHostPort returns host:port for display; IPv6 hosts are bracketed.
func FormatHostPort(host, port string) string {
	if port == "" {
		port = "5432"
	}
	if strings.Contains(host, ":") {
		return net.JoinHostPort(host, port)
	}
	return host + ":" + port
}
