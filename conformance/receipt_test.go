package conformance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/receipt"
)

const receiptDir = "../testdata/golden/demo-site-receipts"

func TestDemoReceiptChainReplays(t *testing.T) {
	paths := []string{
		filepath.Join(receiptDir, "demo-site-boundary.json"),
		filepath.Join(receiptDir, "demo-site-packet.json"),
		filepath.Join(receiptDir, "demo-site-replay.json"),
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receipt.Validate(data); err != nil {
			t.Errorf("verify %s: %v", filepath.Base(p), err)
		}
	}
	res, err := receipt.Replay(paths)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReceiptCount != 3 {
		t.Errorf("receipt count = %d", res.ReceiptCount)
	}
	const wantHead = "bb79b7ba13bfc8b657a532c9a07cd3eb9c27020514c903e9cda4385f6e5012eb"
	if res.ChainHeadEventHash != wantHead {
		t.Errorf("chain head = %s, want %s", res.ChainHeadEventHash, wantHead)
	}
}

func TestReceiptCreateRoundTrips(t *testing.T) {
	body, err := receipt.Create(receipt.CreateParams{
		Action: "demo.test", Actor: "tester", SubjectType: "demo", SubjectRef: "demo://x",
		Timestamp: "2026-10-02T07:40:00Z", ReceiptID: "receipt_test",
		EvidenceRefs: []string{"docs/x.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receipt.Validate(body); err != nil {
		t.Errorf("created receipt failed validation: %v", err)
	}
}

func TestReceiptForbiddenContentRejected(t *testing.T) {
	body, _ := receipt.Create(receipt.CreateParams{
		Action: "ok", Actor: "a", SubjectType: "s", SubjectRef: "r",
		Timestamp: "2026-10-02T07:40:00Z", ReceiptID: "receipt_x",
	})
	// Inject a forbidden value into the action field.
	tampered := []byte(string(body))
	tampered = []byte(replaceOnce(string(tampered), `"action":"ok"`, `"action":"token=abcdefabcdefabcdefabcdef"`))
	if _, err := receipt.Validate(tampered); err == nil {
		t.Error("expected forbidden content to be rejected")
	}
}

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
