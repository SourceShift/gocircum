package securerandom

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// Int generates a cryptographically secure random integer in the range [min, max].
// If the crypto/rand source fails, it returns an error instead of falling back to
// an insecure source.
func Int(min, max int) (int, error) {
	if min < 0 || max < 0 {
		return 0, fmt.Errorf("negative numbers not supported")
	}
	if min > max {
		return 0, fmt.Errorf("min cannot be greater than max")
	}
	if min == max {
		return min, nil
	}

	// Calculate the range size
	rangeSize := big.NewInt(int64(max - min + 1))

	// Generate a secure random number
	num, err := rand.Int(rand.Reader, rangeSize)
	if err != nil {
		return 0, fmt.Errorf("failed to generate secure random number: %w", err)
	}

	return int(num.Int64()) + min, nil
}

// MustInt generates a cryptographically secure random integer in the range [min, max].
// If the crypto/rand source fails, it panics with an error message.
// This should only be used when failure to generate a secure random number is catastrophic.
func MustInt(min, max int) int {
	result, err := Int(min, max)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: Cannot generate secure random number: %v", err))
	}
	return result
}

// Float64 returns a cryptographically secure random float in the range [0.0, 1.0).
// If the crypto/rand source fails, it returns an error instead of falling back to
// an insecure source.
func Float64() (float64, error) {
	// We need a random 64-bit value
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, fmt.Errorf("failed to generate secure random float: %w", err)
	}

	// Convert to uint64, then scale to [0, 1)
	val := binary.BigEndian.Uint64(buf[:])
	// Dividing by (1<<53) gives a float64 with 53 bits of precision (the max for float64)
	return float64(val&((1<<53)-1)) / (1 << 53), nil
}

// MustFloat64 returns a cryptographically secure random float in the range [0.0, 1.0).
// If the crypto/rand source fails, it panics with an error message.
// This should only be used when failure to generate a secure random number is catastrophic.
func MustFloat64() float64 {
	result, err := Float64()
	if err != nil {
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: Cannot generate secure random float: %v", err))
	}
	return result
}

// Bytes fills the given slice with random bytes from a cryptographically secure source.
// If the crypto/rand source fails, it returns an error instead of falling back to
// an insecure source.
func Bytes(b []byte) error {
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return nil
}

// Duration returns a cryptographically secure random duration between min and max.
// If the crypto/rand source fails, it returns an error instead of falling back to
// an insecure source.
func Duration(min, max time.Duration) (time.Duration, error) {
	if min > max {
		return 0, fmt.Errorf("min duration cannot be greater than max")
	}
	if min == max {
		return min, nil
	}

	// Convert to nanoseconds for integer range
	minNs := min.Nanoseconds()
	maxNs := max.Nanoseconds()

	// Get a random value in the range
	valNs, err := Int(int(minNs), int(maxNs))
	if err != nil {
		return 0, err
	}

	return time.Duration(valNs), nil
}

// MustDuration returns a cryptographically secure random duration between min and max.
// If the crypto/rand source fails, it panics with an error message.
// This should only be used when failure to generate a secure random number is catastrophic.
func MustDuration(min, max time.Duration) time.Duration {
	result, err := Duration(min, max)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: Cannot generate secure random duration: %v", err))
	}
	return result
}

// Perm returns a random permutation of integers [0,n).
// It uses cryptographically secure randomness and returns an error if secure
// randomness cannot be generated.
func Perm(n int) ([]int, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n must be greater than 0")
	}

	result := make([]int, n)
	for i := 0; i < n; i++ {
		result[i] = i
	}

	// Fisher-Yates shuffle with cryptographic randomness
	for i := n - 1; i > 0; i-- {
		j, err := Int(0, i)
		if err != nil {
			return nil, fmt.Errorf("failed to generate secure random number for permutation: %w", err)
		}
		result[i], result[j] = result[j], result[i]
	}

	return result, nil
}

// MustPerm returns a random permutation of integers [0,n).
// It uses cryptographically secure randomness and panics if secure
// randomness cannot be generated. This should only be used when failure
// to generate a secure random number is catastrophic.
func MustPerm(n int) []int {
	result, err := Perm(n)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: Cannot generate secure permutation: %v", err))
	}
	return result
}

// Shuffle securely shuffles the elements of a slice using the Fisher-Yates algorithm
// with cryptographic randomness. If the crypto/rand source fails, it returns an error
// instead of falling back to an insecure source.
func Shuffle(slice interface{}, swap func(i, j int)) error {
	// Get the length of the slice through reflection
	n := 0
	switch s := slice.(type) {
	case []int:
		n = len(s)
	case []string:
		n = len(s)
	case []byte:
		n = len(s)
	case []float64:
		n = len(s)
	default:
		// Try to determine length safely with a limited number of attempts
		n = 0
		maxTries := 1000 // Set a reasonable upper limit

		for i := 0; i < maxTries; i++ {
			success := true
			func() {
				defer func() {
					if r := recover(); r != nil {
						success = false
					}
				}()
				swap(i, i) // Test if this index is valid
			}()

			if !success {
				break // We've hit the end of the slice
			}
			n = i + 1
		}

		if n == 0 {
			return fmt.Errorf("could not determine slice length or slice is empty")
		}
	}

	if n <= 1 {
		return nil
	}

	for i := n - 1; i > 0; i-- {
		j, err := Int(0, i)
		if err != nil {
			return err
		}
		swap(i, j)
	}

	return nil
}

// MustShuffle securely shuffles the elements of a slice using the Fisher-Yates algorithm
// with cryptographic randomness. If the crypto/rand source fails, it panics with an error message.
// This should only be used when failure to generate a secure random number is catastrophic.
func MustShuffle(slice interface{}, swap func(i, j int)) {
	err := Shuffle(slice, swap)
	if err != nil {
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: Cannot perform secure shuffle: %v", err))
	}
}

// FailSecurely logs a security error and returns a default value.
// This is only for non-security-critical code paths where a failure to generate
// secure randomness is acceptable, and the default value is safe to use.
// THIS SHOULD BE USED WITH EXTREME CAUTION.
func FailSecurely(err error, defaultValue interface{}, securityContext string) interface{} {
	logger := logging.GetLogger()
	logger.Error("SECURITY ALERT: Failed to generate secure random number",
		"error", err,
		"context", securityContext,
		"action", "using safe default value")

	// Return the provided default value
	return defaultValue
}
