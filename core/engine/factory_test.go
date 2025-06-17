package engine

import (
	"gocircum/core/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildQUICUTLSConfig(t *testing.T) {
	t.Run("DefaultIsSecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
		}
		utlsConfig, err := buildQUICUTLSConfig(cfg, nil)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify, "InsecureSkipVerify should be false by default")
	})
}
