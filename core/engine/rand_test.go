package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoRandInt(t *testing.T) {
	t.Run("ValidRange", func(t *testing.T) {
		min, max := 10, 20
		for i := 0; i < 100; i++ {
			n, err := cryptoRandInt(min, max)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, n, min)
			assert.LessOrEqual(t, n, max)
		}
	})

	t.Run("SingleValueRange", func(t *testing.T) {
		val := 42
		n, err := cryptoRandInt(val, val)
		require.NoError(t, err)
		assert.Equal(t, val, n)
	})

	t.Run("InvalidRange", func(t *testing.T) {
		_, err := cryptoRandInt(20, 10)
		assert.Error(t, err)
	})

	t.Run("ZeroRange", func(t *testing.T) {
		n, err := cryptoRandInt(0, 0)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("NegativeRange", func(t *testing.T) {
		min, max := -20, -10
		// This should fail because crypto/rand only works with non-negative numbers.
		// Our implementation should handle this gracefully.
		// The current implementation of cryptoRandInt does not support negative numbers.
		// We expect an error in this case.
		_, err := cryptoRandInt(min, max)
		assert.Error(t, err)
	})
}
