package dpop

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// TargetURI returns the "htu" value for a request URI: the absolute http or
// https URI without its query and fragment, normalized with the
// syntax-based (RFC 3986 §6.2.2) and scheme-based (RFC 3986 §6.2.3) rules
// that RFC 9449 recommends before comparison:
//
//   - scheme and host are lowercased, and a default port (80 for http,
//     443 for https) is removed;
//   - an empty path becomes "/";
//   - percent-encodings of unreserved characters are decoded and other
//     percent-encodings use uppercase hex;
//   - "." and ".." segments are removed.
//
// URIs with user information are rejected, because a proof must not carry
// credentials.
//
// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2
// https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3
func TargetURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("dpop: target URI: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("dpop: target URI must be an absolute http or https URI")
	}
	if u.User != nil {
		return "", fmt.Errorf("dpop: target URI must not contain user information")
	}
	if u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("dpop: target URI must have a host")
	}

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" || strings.Contains(host, ":") {
		// Bracket IPv6 literals, and keep any non-default port.
		if port == "" {
			host = "[" + host + "]"
		} else {
			host = net.JoinHostPort(host, port)
		}
	}

	path := normalizePercentEncoding(u.EscapedPath())
	path = removeDotSegments(path)
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// normalizePercentEncoding decodes percent-encoded unreserved characters and
// uppercases the hex digits of the rest (RFC 3986 §6.2.2.1, §6.2.2.2).
func normalizePercentEncoding(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				c := hi<<4 | lo
				if isUnreserved(c) {
					b.WriteByte(c)
				} else {
					b.WriteByte('%')
					b.WriteString(strings.ToUpper(s[i+1 : i+3]))
				}
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// removeDotSegments implements RFC 3986 §5.2.4.
func removeDotSegments(in string) string {
	var out []string
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "/..":
			in = "/"
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "." || in == "..":
			in = ""
		default:
			start := 0
			if in[0] == '/' {
				start = 1
			}
			end := strings.IndexByte(in[start:], '/')
			if end < 0 {
				end = len(in)
			} else {
				end += start
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}
