// Package ndjson reads and writes newline-delimited JSON the way the shell
// build's `jq -cn` does: one compact object per line, keys in the order the
// writer gave them, and jq's string escaping rules.
package ndjson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Field is one key/value pair in an ordered object.
type Field struct {
	Key   string
	Value any
}

// Object is an ordered JSON object.
type Object []Field

// Encode renders the object compactly with jq-compatible escaping.
func Encode(obj Object) []byte {
	var b bytes.Buffer
	writeObject(&b, obj)
	return b.Bytes()
}

func writeObject(b *bytes.Buffer, obj Object) {
	b.WriteByte('{')
	for i, f := range obj {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, f.Key)
		b.WriteByte(':')
		writeValue(b, f.Value)
	}
	b.WriteByte('}')
}

func writeValue(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		writeString(b, x)
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		b.WriteString(strconv.FormatFloat(x, 'f', -1, 64))
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeValue(b, e)
		}
		b.WriteByte(']')
	case Object:
		writeObject(b, x)
	case json.RawMessage:
		b.Write(bytes.TrimSpace(x))
	default:
		enc, err := json.Marshal(x)
		if err != nil {
			writeString(b, fmt.Sprint(x))
			return
		}
		b.Write(enc)
	}
}

// writeString follows jq: escape quote, backslash and control characters,
// using the short forms jq uses, and pass everything else through as UTF-8.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			default:
				if c < 0x20 || c == 0x7f {
					fmt.Fprintf(b, `\u%04x`, c)
				} else {
					b.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString("�")
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

// Record is a decoded line. Values are the generic JSON types.
type Record map[string]any

// String returns the string value of key, or "" when absent or not a string.
func (r Record) String(key string) string {
	if v, ok := r[key].(string); ok {
		return v
	}
	return ""
}

// Bool returns the boolean value of key.
func (r Record) Bool(key string) bool {
	v, _ := r[key].(bool)
	return v
}

// Strings returns the string array at key.
func (r Record) Strings(key string) []string {
	arr, ok := r[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ReadFile parses every non-blank line of an NDJSON file. A missing file
// yields no records and no error, matching the shell build's `[ -s file ]`.
func ReadFile(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("%s: line %d: %w", path, lineNo, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

// Latest returns a map of id -> last record with that id, preserving the
// shell build's `reduce .[] as $r ({}; .[$r.id] = $r)` semantics, plus the
// ids in first-seen order.
func Latest(records []Record) (map[string]Record, []string) {
	byID := map[string]Record{}
	var order []string
	for _, r := range records {
		id := r.String("id")
		if _, seen := byID[id]; !seen {
			order = append(order, id)
		}
		byID[id] = r
	}
	return byID, order
}

// Append writes one encoded object plus newline to path, creating it 0600.
func Append(path string, obj Object) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line := append(Encode(obj), '\n')
	_, err = f.Write(line)
	return err
}

// Decode parses one JSON document, keeping numbers as json.Number so that
// Canonical can print them the way jq does.
func Decode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}

// Canonical renders a decoded value like `jq -cS .`: compact, object keys
// sorted, jq string escaping.
func Canonical(v any) []byte {
	var b bytes.Buffer
	writeCanonical(&b, v)
	return b.Bytes()
}

func writeCanonical(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			writeCanonical(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, e)
		}
		b.WriteByte(']')
	case json.Number:
		b.WriteString(x.String())
	default:
		writeValue(b, v)
	}
}
