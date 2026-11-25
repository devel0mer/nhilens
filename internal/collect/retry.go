package collect

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

// RetryPolicy controls exponential backoff retries for throttled AWS calls.
type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Sleep       func(ctx context.Context, d time.Duration) error
}

// DefaultRetryPolicy returns conservative retry settings suitable for IAM APIs.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   200 * time.Millisecond,
		MaxDelay:    5 * time.Second,
		Sleep:       contextSleep,
	}
}

func (p RetryPolicy) normalize() RetryPolicy {
	out := p
	if out.MaxAttempts <= 0 {
		out.MaxAttempts = 5
	}
	if out.BaseDelay <= 0 {
		out.BaseDelay = 200 * time.Millisecond
	}
	if out.MaxDelay <= 0 {
		out.MaxDelay = 5 * time.Second
	}
	if out.Sleep == nil {
		out.Sleep = contextSleep
	}
	return out
}

func contextSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// IsThrottlingError reports whether err represents an AWS throttling or transient rate-limit error.
func IsThrottlingError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "Throttling",
			"ThrottlingException",
			"TooManyRequestsException",
			"RequestLimitExceeded",
			"LimitExceeded",
			"RateExceeded",
			"SlowDown",
			"PriorRequestNotComplete",
			"ServiceUnavailable":
			return true
		}
	}
	return false
}

// IsNoSuchEntityError reports whether err is an IAM NoSuchEntity response
// (for example, GetLoginProfile when a user has no console password).
func IsNoSuchEntityError(err error) bool {
	if err == nil {
		return false
	}
	var noSuch *iamtypes.NoSuchEntityException
	if errors.As(err, &noSuch) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchEntity"
	}
	return false
}

// DoWithRetry executes fn and retries with exponential backoff + jitter on AWS throttling errors.
func DoWithRetry[T any](ctx context.Context, rp RetryPolicy, fn func(context.Context) (T, error)) (T, error) {
	rp = rp.normalize()
	var zero T

	for attempt := 1; attempt <= rp.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}

		res, err := fn(ctx)
		if err == nil {
			return res, nil
		}
		if !IsThrottlingError(err) || attempt == rp.MaxAttempts {
			return zero, err
		}

		delay := rp.BaseDelay << uint(attempt-1)
		if delay > rp.MaxDelay || delay <= 0 {
			delay = rp.MaxDelay
		}
		// Add up to 25% jitter to spread concurrent retries.
		jitter := time.Duration(rand.Int64N(int64(delay/4) + 1))
		if sleepErr := rp.Sleep(ctx, delay+jitter); sleepErr != nil {
			return zero, sleepErr
		}
	}

	return zero, context.DeadlineExceeded
}
