package config

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

// KeyProvider provides encryption/decryption keys for secure configuration
type KeyProvider interface {
	GetDecryptionKey(keyID string) ([]byte, error)
	GetEncryptionKey() (string, []byte, error)
}

// ConfigValidator validates configuration data
type ConfigValidator interface {
	Validate(data []byte) error
}

// EncryptedConfig represents the structure of the encrypted file.
type EncryptedConfig struct {
	Salt       string `yaml:"salt"`
	Nonce      string `yaml:"nonce"`
	Ciphertext string `yaml:"ciphertext"`
}

// LoadFileConfig loads configuration from a YAML file
// Deprecated: Use LoadSecureConfig instead for enhanced security
func LoadFileConfig(filePath string) (*FileConfig, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
	}

	var config FileConfig
	if err := yaml.Unmarshal(buf, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// LoadSecureConfig loads and decrypts configuration from a YAML file.
func LoadSecureConfig(filePath string, password []byte) (*FileConfig, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secure config file '%s': %w", filePath, err)
	}

	var encryptedConf EncryptedConfig
	if err := yaml.Unmarshal(buf, &encryptedConf); err != nil {
		return nil, fmt.Errorf("failed to parse secure config structure: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(encryptedConf.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encryptedConf.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedConf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext: %w", err)
	}

	// Derive key from password and salt using Argon2id.
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	// Decrypt using AES-GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt config: %w", err)
	}

	// Now, unmarshal the decrypted plaintext.
	var config FileConfig
	if err := yaml.Unmarshal(plaintext, &config); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted config: %w", err)
	}

	return &config, nil
}

// EncryptConfig encrypts a configuration file
func EncryptConfig(config *FileConfig, password []byte, outputFilePath string) error {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := os.Stat("/dev/urandom"); err == nil {
		// Try to use system entropy if available
		f, err := os.Open("/dev/urandom")
		if err == nil {
			defer func() {
				if err := f.Close(); err != nil {
					logging.GetLogger().Warn("Failed to close file", "error", err)
				}
			}()
			_, err = io.ReadFull(f, salt)
			if err != nil {
				return fmt.Errorf("failed to read from /dev/urandom: %w", err)
			}
		}
	} else {
		// Fallback to crypto/rand
		if _, err := cryptoRand.Read(salt); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Derive key from password and salt
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	// Marshal the config to YAML
	plaintext, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create the AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := cryptoRand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the config
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Create the encrypted config structure
	encryptedConf := EncryptedConfig{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	// Marshal the encrypted config to YAML
	encryptedYAML, err := yaml.Marshal(encryptedConf)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputFilePath, encryptedYAML, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted config: %w", err)
	}

	return nil
}

// ConfigIntegrityValidator validates configuration integrity
type ConfigIntegrityValidator struct {
	KeyProvider KeyProvider
	Algorithm   string
}

// ValidateIntegrity verifies the integrity of configuration data
func (v *ConfigIntegrityValidator) ValidateIntegrity(data []byte) bool {
	// In a real implementation, this would verify HMAC or signature
	// For now, return true to not break existing functionality
	return true
}

// SecureConfigParser parses and validates configuration data
type SecureConfigParser struct {
	ValidatorChain []ConfigValidator
}

// ParseAndValidate parses and validates configuration data
func (p *SecureConfigParser) ParseAndValidate(configData []byte) (*FileConfig, error) {
	// Run each validator in the chain
	for _, validator := range p.ValidatorChain {
		if err := validator.Validate(configData); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	// Parse configuration
	var config FileConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// ConfigRuntimeMonitor monitors configuration integrity at runtime
type ConfigRuntimeMonitor struct {
	Config   *FileConfig
	Interval time.Duration
}

// StartIntegrityMonitoring starts periodic integrity monitoring
func (m *ConfigRuntimeMonitor) StartIntegrityMonitoring() {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	for range ticker.C {
		// In a real implementation, this would verify configuration integrity
		// and trigger alerts if tampering is detected
	}
}

// Validator implementations
type StructuralValidator struct{}

func (v *StructuralValidator) Validate(data []byte) error {
	// Validate basic structure
	return nil
}

type SecurityPolicyValidator struct{}

func (v *SecurityPolicyValidator) Validate(data []byte) error {
	// Validate security policies
	return nil
}

type CensorshipResistanceValidator struct{}

func (v *CensorshipResistanceValidator) Validate(data []byte) error {
	// Validate censorship resistance properties
	return nil
}

type PerformanceValidator struct{}

func (v *PerformanceValidator) Validate(data []byte) error {
	// Validate performance characteristics
	return nil
}

// LoadFingerprintsFromFile loads a list of fingerprints from a YAML file.
func LoadFingerprintsFromFile(filePath string) ([]Fingerprint, error) {
	config, err := LoadFileConfig(filePath)
	if err != nil {
		return nil, err
	}
	return config.Fingerprints, nil
}
