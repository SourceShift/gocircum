package engine

import (
	"gocircum/core/config"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildStandardTLSConfig(t *testing.T) {
	t.Run("DefaultIsSecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
		}
		tlsConfig, err := buildStandardTLSConfig("example.com", cfg)
		assert.NoError(t, err)
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("ExplicitlyInsecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			SkipVerify: true,
		}
		tlsConfig, err := buildStandardTLSConfig("example.com", cfg)
		assert.NoError(t, err)
		assert.True(t, tlsConfig.InsecureSkipVerify)
	})

	t.Run("ExplicitlySecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			SkipVerify: false,
		}
		tlsConfig, err := buildStandardTLSConfig("example.com", cfg)
		assert.NoError(t, err)
		assert.False(t, tlsConfig.InsecureSkipVerify)
	})
}

func TestBuildUTLSConfig(t *testing.T) {
	t.Run("DefaultIsSecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
		}
		utlsConfig, err := buildUTLSConfig("example.com", cfg)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify)
	})

	t.Run("ExplicitlyInsecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			SkipVerify: true,
		}
		utlsConfig, err := buildUTLSConfig("example.com", cfg)
		assert.NoError(t, err)
		assert.True(t, utlsConfig.InsecureSkipVerify)
	})

	t.Run("ExplicitlySecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
			SkipVerify: false,
		}
		utlsConfig, err := buildUTLSConfig("example.com", cfg)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify)
	})
}
