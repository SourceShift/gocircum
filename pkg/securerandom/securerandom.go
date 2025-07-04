package securerandom

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// Int returns a cryptographically secure random integer in the range [min, max].
func Int(min, max int) (int, error) {
	if max <= min {
		return 0, fmt.Errorf("max must be greater than min (got min=%d, max=%d)", min, max)
	}

	// Calculate the range size
	rangeSize := int64(max - min + 1)

	// Generate a random integer in the range [0, rangeSize-1]
	nBig, err := rand.Int(rand.Reader, big.NewInt(rangeSize))
	if err != nil {
		return 0, err
	}

	// Convert to int and add min to get a value in the range [min, max]
	return int(nBig.Int64()) + min, nil
}

// MustInt is like Int but panics on error.
// Use this only when an error is truly unexpected and would be fatal to the program.
func MustInt(min, max int) int {
	result, err := Int(min, max)
	if err != nil {
		panic(fmt.Sprintf("securerandom.MustInt: %v", err))
	}
	return result
}

// Perm returns a random permutation of integers [0,n).
func Perm(n int) ([]int, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid argument to Perm: %d", n)
	}

	// Create a slice with values 0 to n-1
	result := make([]int, n)
	for i := range result {
		result[i] = i
	}

	// Shuffle the slice
	err := Shuffle(result, func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Shuffle securely shuffles a slice using the Fisher-Yates algorithm.
// The swap function should exchange the elements at i and j.
func Shuffle(slice interface{}, swap func(i, j int)) error {
	// Determine the length of the slice based on the number of calls to swap
	length := 0

	// Get the length from slice
	switch s := slice.(type) {
	case []int:
		length = len(s)
	case []string:
		length = len(s)
	case []byte:
		length = len(s)
	case []float64:
		length = len(s)
	case []rune:
		length = len(s)
	case []bool:
		length = len(s)
	default:
		// Try to infer the length from the first few calls
		// This won't work for all types but is a best effort
		if swappable, ok := slice.(interface{ Len() int }); ok {
			length = swappable.Len()
		} else {
			return errors.New("could not determine length of slice")
		}
	}

	// No need to shuffle a slice of length 0 or 1
	if length <= 1 {
		return nil
	}

	// Fisher-Yates shuffle
	for i := length - 1; i > 0; i-- {
		// Generate a random index j such that 0 <= j <= i
		j, err := Int(0, i)
		if err != nil {
			return err
		}

		// Swap elements i and j
		swap(i, j)
	}

	return nil
}

// GetRandomBytes returns n cryptographically secure random bytes.
func GetRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// MustGetRandomBytes is like GetRandomBytes but panics on error.
func MustGetRandomBytes(n int) []byte {
	b, err := GetRandomBytes(n)
	if err != nil {
		panic(fmt.Sprintf("securerandom.MustGetRandomBytes: %v", err))
	}
	return b
}

// Float64 returns a random float64 in the range [0.0,1.0).
func Float64() (float64, error) {
	// Generate 8 random bytes
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}

	// Convert bytes to uint64 and scale to [0,1)
	return float64(binary.BigEndian.Uint64(b)) / (1 << 64), nil
}

// MustFloat64 is like Float64 but panics on error.
func MustFloat64() float64 {
	result, err := Float64()
	if err != nil {
		panic(fmt.Sprintf("securerandom.MustFloat64: %v", err))
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
