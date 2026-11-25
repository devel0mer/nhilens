package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExitError wraps an error with an explicit process exit code (e.g., for --fail-on).
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// ParseDuration parses a positive duration string supporting day suffixes (e.g. "90d")
// in addition to standard Go duration syntax (e.g. "24h", "30m").
func ParseDuration(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, fmt.Errorf("duration cannot be empty")
	}

	var d time.Duration
	var err error
	if strings.HasSuffix(s, "d") && !strings.ContainsAny(s[:len(s)-1], "hmsuµn") {
		daysStr := strings.TrimSuffix(s, "d")
		days, convErr := strconv.Atoi(daysStr)
		if convErr != nil {
			return 0, fmt.Errorf("invalid day duration %q: %w", raw, convErr)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		d, err = time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", raw, err)
		}
	}

	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive, got %q", raw)
	}
	return d, nil
}

// ParseSeverity validates and normalizes a severity threshold for --fail-on.
// An empty string disables threshold failure.
func ParseSeverity(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "", "low", "medium", "high", "critical":
		return s, nil
	default:
		return "", fmt.Errorf("invalid severity %q (expected one of: low, medium, high, critical)", raw)
	}
}
