package engine

import (
	"gocircum/core/config"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUTLSConfig(t *testing.T) {
	t.Run("DefaultIsSecure", func(t *testing.T) {
		cfg := &config.TLS{MinVersion: "1.2", MaxVersion: "1.3"}
		utlsConfig, err := buildUTLSConfig("example.com", cfg, nil)
		require.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify)
	})
}
