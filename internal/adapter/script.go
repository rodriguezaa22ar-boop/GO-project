package adapter

import (
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func init() { register(scriptAdapter{}) }

// scriptAdapter runs an arbitrary operator-provided command as evidence
// capture only; it does not parse output. The operator must declare the
// tier with a leading --tier 1 or --tier 2. An undeclared tier counts as
// Tier 3 and is refused, so a script can never silently run at a higher
// tier than the operator claimed.
type scriptAdapter struct{}

func (scriptAdapter) Name() string { return "script" }

func (scriptAdapter) Capability(args []string) (string, error) {
	tier, _, err := splitTier(args)
	if err != nil {
		return "", err
	}
	switch tier {
	case 1:
		return scope.PassiveRecon, nil
	case 2:
		return scope.ActiveRecon, nil
	default:
		// Undeclared or higher: treat as safe-validation (tier 3), which the
		// runner then refuses.
		return scope.SafeValidation, nil
	}
}

func (scriptAdapter) Command(t Target, args []string) ([]string, error) {
	_, rest, err := splitTier(args)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, state.Failf("script adapter requires a command after --tier <1|2>")
	}
	return rest, nil
}

func (scriptAdapter) Parse(out []byte) []ProposedFinding { return nil }

// splitTier reads a leading "--tier N" from args and returns the tier (0
// when absent) and the remaining argv.
func splitTier(args []string) (int, []string, error) {
	if len(args) >= 2 && args[0] == "--tier" {
		switch args[1] {
		case "1":
			return 1, args[2:], nil
		case "2":
			return 2, args[2:], nil
		default:
			return 0, nil, state.Failf("script adapter --tier must be 1 or 2, got: %s", args[1])
		}
	}
	return 0, args, nil
}
