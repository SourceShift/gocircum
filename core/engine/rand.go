package engine

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// cryptoRandInt generates a cryptographically secure random integer in the range [min, max].
// It uses crypto/rand for security.
func cryptoRandInt(min, max int) (int, error) {
	if min < 0 || max < 0 {
		return 0, fmt.Errorf("crypto/rand does not support negative numbers")
	}
	if min > max {
		return 0, fmt.Errorf("min cannot be greater than max")
	}

	if min == max {
		return min, nil
	}

	// Calculate the range of random numbers.
	// Add 1 to make the range inclusive of max.
	valRange := big.NewInt(int64(max - min + 1))

	// Generate a cryptographically secure random number in [0, valRange-1].
	n, err := rand.Int(rand.Reader, valRange)
	if err != nil {
		return 0, fmt.Errorf("failed to generate crypto/rand integer: %w", err)
	}

	// Add the random number to min to get a result in the [min, max] range.
	return int(n.Int64()) + min, nil
}
