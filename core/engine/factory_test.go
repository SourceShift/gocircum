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
		utlsConfig, err := buildQUICUTLSConfig(cfg)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify, "InsecureSkipVerify should be false by default")
	})

	t.Run("InsecureIsIgnored", func(t *testing.T) {
		skipVerify := true
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			SkipVerify: &skipVerify,
		}
		utlsConfig, err := buildQUICUTLSConfig(cfg)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify, "InsecureSkipVerify should be false even when skip_verify is true")
	})

	t.Run("ExplicitlySecure", func(t *testing.T) {
		skipVerify := false
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			SkipVerify: &skipVerify,
		}
		utlsConfig, err := buildQUICUTLSConfig(cfg)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify, "InsecureSkipVerify should be false when explicitly set")
	})
}
