package packet

import (
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// TrustChain is the metadata-chain status Lite can assess: archive status
// plus packet verifications. It deliberately does not evaluate v1 readiness,
// which in the shell build checks for the presence of the atlas/wiremap/
// vector/intelctl toolchain that Lite does not ship.
type TrustChain struct {
	Status               string
	NextStep             string
	Readiness            *readiness.State
	ArchiveStatus        string
	CloseoutVerification string
	CloseoutProblems     int
	AuditVerification    string
	ArchiveVerification  string
	ReviewVerification   string
	CloseoutPath         string
	AuditPath            string
	ArchivePath          string
}

// CollectTrustChain gathers the metadata-chain state for an operation.
func CollectTrustChain(op *operation.Operation) (*TrustChain, error) {
	st, err := readiness.Collect(op)
	if err != nil {
		return nil, err
	}
	tc := &TrustChain{Readiness: st}
	tc.CloseoutVerification, tc.CloseoutPath, tc.CloseoutProblems = closeoutVerificationStatus(op, st)
	tc.AuditVerification, tc.AuditPath = auditPacketVerificationStatus(op, st)
	tc.ReviewVerification, _ = reviewPacketVerificationStatus(st)
	tc.ArchiveStatus = archiveStatus(st, tc.CloseoutVerification, tc.AuditVerification, tc.ReviewVerification)

	archiveVerification := "missing"
	if st.ArchivePacket.Present() && state.FileExists(st.ArchivePacket.Detail) {
		tc.ArchivePath = st.ArchivePacket.Detail
		res, err := ArchiveVerify(op, tc.ArchivePath)
		if err != nil || res.Status != "verified" {
			archiveVerification = "attention-required"
		} else {
			archiveVerification = "verified"
		}
	}
	tc.ArchiveVerification = archiveVerification

	switch {
	case tc.ArchiveStatus != "current":
		tc.Status = tc.ArchiveStatus
		tc.NextStep = archiveNextStep(st, tc.CloseoutVerification, tc.AuditVerification, tc.ReviewVerification)
	case tc.ArchiveVerification != "verified":
		tc.Status = "attention-required"
		tc.NextStep = "Resolve archive packet verification issues before trust-chain closeout."
	default:
		tc.Status = "current"
		tc.NextStep = "Metadata trust chain is current. Lite does not certify v1 production readiness."
	}
	return tc, nil
}
