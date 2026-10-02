package envfile

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var quoteCases = []string{
	"", "plain", "a b", "it's", `a"b`, "a,b", "a=b", "a:b", "a/b", "a@b", "a%b",
	"a+b", "a#b", "#a", "~a", "a~b", "a!b", "a$b", "a`b", `a\b`, "a|b", "a&b",
	"a;b", "a(b", "a)b", "a<b", "a>b", "a{b", "a}b", "a[b", "a]b", "a*b", "a?b",
	"a^b", " a", "a ", "ñ", "a\tb", "a\nb", "a'b c", "é ü", `x\\y`, "a\rb",
	"a\x01b", "a\x7fb", "a\x1bb", "'\n", "prototype learning",
	"authorized metadata-only learning operation using claude",
	"Bounded authorized Hack The Box Starting Point assessment for the named target through the operator's active VPN or lab connection.",
}

func TestQuoteMatchesBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, s := range quoteCases {
		cmd := exec.Command("bash", "-c", `printf '%q' "$1"`, "_", s)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash printf failed for %q: %v", s, err)
		}
		if got := Quote(s); got != string(out) {
			t.Errorf("Quote(%q) = %s, bash = %s", s, got, out)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, s := range quoteCases {
		rec, err := Parse([]byte("K=" + Quote(s) + "\n"))
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		if got := rec.Get("K"); got != s {
			t.Errorf("round trip %q -> %q", s, got)
		}
	}
}

func TestParseDoubleQuotedProfile(t *testing.T) {
	src := "PROFILE_NAME=htb-starting-point\n" +
		"PROFILE_SUMMARY=\"Hack The Box Starting Point authorized lab profile\"\n" +
		"SCOPE_TEXT=\"Bounded assessment through the operator's active VPN.\"\n" +
		"EMPTY=''\n" +
		"TAGS=prototype\\ learning\n"
	rec, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Get("PROFILE_SUMMARY") != "Hack The Box Starting Point authorized lab profile" {
		t.Errorf("double quote parse: %q", rec.Get("PROFILE_SUMMARY"))
	}
	if rec.Get("SCOPE_TEXT") != "Bounded assessment through the operator's active VPN." {
		t.Errorf("apostrophe in double quotes: %q", rec.Get("SCOPE_TEXT"))
	}
	if rec.Get("EMPTY") != "" || !rec.Has("EMPTY") {
		t.Errorf("empty value")
	}
	if rec.Get("TAGS") != "prototype learning" {
		t.Errorf("backslash space: %q", rec.Get("TAGS"))
	}
}

func TestUpsertMovesKeyToEnd(t *testing.T) {
	rec := New()
	rec.Upsert("A", "1")
	rec.Upsert("B", "2")
	rec.Upsert("A", "3")
	got := string(rec.Bytes())
	if got != "B=2\nA=3\n" {
		t.Errorf("upsert order: %q", got)
	}
	if strings.Count(got, "A=") != 1 {
		t.Errorf("duplicate key after upsert")
	}
}

func TestShellBuildFilesRoundTripByteIdentical(t *testing.T) {
	// Files written by the shell build (printf %q) must re-serialize identically.
	for _, name := range []string{"session.env", "scope.snapshot.env", "target.env"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(rec.Bytes(), data) {
			t.Errorf("%s: re-serialized bytes differ\n--- got\n%s--- want\n%s", name, rec.Bytes(), data)
		}
	}
	// Profiles are hand-written with double quotes; they must parse, not round trip.
	rec, err := Load("testdata/profile.env")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Get("VALIDATION_LANES") != "validate posture" {
		t.Errorf("profile parse: %q", rec.Get("VALIDATION_LANES"))
	}
}
