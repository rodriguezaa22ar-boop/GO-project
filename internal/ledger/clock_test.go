package ledger

import (
	"time"

	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

var defaultClock = state.Now

func fixedClock(ts string) func() time.Time {
	t, err := time.Parse("2006-01-02T15:04:05Z", ts)
	if err != nil {
		panic(err)
	}
	return func() time.Time { return t }
}
