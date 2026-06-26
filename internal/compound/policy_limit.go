package compound

import (
	"fmt"
	"strings"
)

// PolicyLimitError reports a factory policy attempt limit that blocked a
// pipeline step before another autonomous attempt could start.
type PolicyLimitError struct {
	PolicyField string
	Step        string
	Attempts    int
	Limit       int
}

func (e *PolicyLimitError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("factory policy blocked %s: %s", strings.TrimSpace(e.PolicyField), e.Reason())
}

// Reason returns the safe policy decision reason for timeline metadata.
func (e *PolicyLimitError) Reason() string {
	if e == nil {
		return ""
	}
	step := strings.TrimSpace(e.Step)
	if step == "" {
		step = "pipeline"
	}
	return fmt.Sprintf("reached attempt limit %d before %s step (attempts=%d)", e.Limit, step, e.Attempts)
}
