// Package envfile reads and writes the shell-sourced KEY=value records that
// the Atlas shell build uses for targets, operations, scope snapshots and
// profiles. Writes reproduce bash's printf %q quoting byte for byte so that
// either implementation can read the other's files.
package envfile

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// Record is an ordered set of key/value pairs. Order matters because the
// shell build's upsert removes a key and re-appends it at the end.
type Record struct {
	keys   []string
	values map[string]string
}

// New returns an empty record.
func New() *Record {
	return &Record{values: map[string]string{}}
}

// Get returns the value for key, or "" when absent.
func (r *Record) Get(key string) string {
	if r == nil {
		return ""
	}
	return r.values[key]
}

// Has reports whether key is present.
func (r *Record) Has(key string) bool {
	_, ok := r.values[key]
	return ok
}

// Keys returns the keys in file order.
func (r *Record) Keys() []string {
	out := make([]string, len(r.keys))
	copy(out, r.keys)
	return out
}

// Upsert mirrors the shell build's upsert_env: any existing line for key is
// removed and the new value is appended at the end.
func (r *Record) Upsert(key, value string) {
	if _, ok := r.values[key]; ok {
		filtered := r.keys[:0]
		for _, k := range r.keys {
			if k != key {
				filtered = append(filtered, k)
			}
		}
		r.keys = filtered
	}
	r.keys = append(r.keys, key)
	r.values[key] = value
}

// Bytes renders the record as the shell build would write it.
func (r *Record) Bytes() []byte {
	var b bytes.Buffer
	for _, k := range r.keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(Quote(r.values[k]))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Load parses an env file from disk.
func Load(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Save writes the record to path with mode 0600.
func Save(path string, r *Record) error {
	return os.WriteFile(path, r.Bytes(), 0o600)
}

// UpsertFile loads path (or starts empty), upserts key and writes it back.
func UpsertFile(path, key, value string) error {
	rec, err := Load(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		rec = New()
	}
	rec.Upsert(key, value)
	return Save(path, rec)
}

// Parse decodes the subset of shell syntax the Atlas files use: bare words
// with backslash escapes, single quotes, double quotes and $'...' ANSI-C
// quoting. Blank lines and comments are skipped.
func Parse(data []byte) (*Record, error) {
	rec := New()
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimLeft(line, " \t")
		if strings.TrimSpace(trimmed) == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("env line %d: expected KEY=value", lineNo)
		}
		key := trimmed[:eq]
		if !validKey(key) {
			return nil, fmt.Errorf("env line %d: invalid key %q", lineNo, key)
		}
		value, err := unquote(trimmed[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("env line %d: %w", lineNo, err)
		}
		rec.Upsert(key, value)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rec, nil
}

func validKey(key string) bool {
	for i, c := range key {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return key != ""
}

func unquote(s string) (string, error) {
	var out strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", fmt.Errorf("unterminated single quote")
			}
			out.WriteString(s[i+1 : i+1+end])
			i += end + 2
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			rest, n, err := unquoteANSI(s[i+2:])
			if err != nil {
				return "", err
			}
			out.WriteString(rest)
			i += 2 + n
		case c == '"':
			i++
			for {
				if i >= len(s) {
					return "", fmt.Errorf("unterminated double quote")
				}
				if s[i] == '"' {
					i++
					break
				}
				if s[i] == '\\' && i+1 < len(s) {
					switch s[i+1] {
					case '"', '\\', '$', '`', '\n':
						out.WriteByte(s[i+1])
						i += 2
						continue
					}
				}
				out.WriteByte(s[i])
				i++
			}
		case c == '\\':
			if i+1 >= len(s) {
				return "", fmt.Errorf("dangling backslash")
			}
			out.WriteByte(s[i+1])
			i += 2
		case c == ' ' || c == '\t':
			// Trailing whitespace or a comment after the value.
			rest := strings.TrimSpace(s[i:])
			if rest != "" && !strings.HasPrefix(rest, "#") {
				return "", fmt.Errorf("unexpected text after value: %q", rest)
			}
			return out.String(), nil
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String(), nil
}

// unquoteANSI decodes the body of a $'...' string, returning the decoded
// text and the number of input bytes consumed including the closing quote.
func unquoteANSI(s string) (string, int, error) {
	var out []byte
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\'' {
			return string(out), i + 1, nil
		}
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(s) {
			return "", 0, fmt.Errorf("dangling backslash in $'' string")
		}
		e := s[i+1]
		switch e {
		case 'a':
			out = append(out, 7)
		case 'b':
			out = append(out, 8)
		case 'e', 'E':
			out = append(out, 27)
		case 'f':
			out = append(out, 12)
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, 11)
		case '\\', '\'', '"', '?':
			out = append(out, e)
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i + 1
			val := 0
			for k := 0; k < 3 && j < len(s) && s[j] >= '0' && s[j] <= '7'; k++ {
				val = val*8 + int(s[j]-'0')
				j++
			}
			out = append(out, byte(val))
			i = j
			continue
		case 'x':
			j := i + 2
			val := 0
			digits := 0
			for digits < 2 && j < len(s) && isHex(s[j]) {
				val = val*16 + hexVal(s[j])
				j++
				digits++
			}
			if digits == 0 {
				out = append(out, '\\', 'x')
				i += 2
				continue
			}
			out = append(out, byte(val))
			i = j
			continue
		default:
			out = append(out, '\\', e)
		}
		i += 2
	}
	return "", 0, fmt.Errorf("unterminated $'' string")
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}

// Quote reproduces bash's printf %q for the given string.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	needsANSI := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			needsANSI = true
			break
		}
	}
	if needsANSI {
		return quoteANSI(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		escape := false
		switch c {
		case ' ', '\t', '\'', '"', ',', '!', '$', '`', '\\', '|', '&', ';',
			'(', ')', '<', '>', '{', '}', '[', ']', '*', '?', '^':
			escape = true
		case '~', '#':
			escape = i == 0
		}
		if escape {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func quoteANSI(s string) string {
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case 7:
			b.WriteString(`\a`)
		case 8:
			b.WriteString(`\b`)
		case 27:
			b.WriteString(`\E`)
		case 12:
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 11:
			b.WriteString(`\v`)
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteString("'")
	return b.String()
}
