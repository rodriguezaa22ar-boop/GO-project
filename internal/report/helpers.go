package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
)

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// sortRemediation mirrors the jq sort_by([severity_weight, updated/created])
// | reverse used in atlas_report_remediation_priorities.
func sortRemediation(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		wi, wj := findings.SeverityWeight(fs[i].SeverityOr()), findings.SeverityWeight(fs[j].SeverityOr())
		if wi != wj {
			return wi < wj
		}
		return strings.Compare(fs[i].UpdatedOrCreated(), fs[j].UpdatedOrCreated()) < 0
	})
	for i, j := 0, len(fs)-1; i < j; i, j = i+1, j-1 {
		fs[i], fs[j] = fs[j], fs[i]
	}
}
