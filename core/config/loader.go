package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigContainer wraps encrypted configuration with metadata
type ConfigContainer struct {
	EncryptedConfig string                `yaml:"encrypted_config,omitempty"`
	DecoyStrategies []Fingerprint         `yaml:"decoy_strategies,omitempty"`
	ConfigMetadata  ConfigMetadata        `yaml:"config_metadata,omitempty"`
	// Include plain config for backward compatibility
	FileConfig      `yaml:",inline"`
}

type ConfigMetadata struct {
	Version          string  `yaml:"version"`
	Encrypted        bool    `yaml:"encrypted"`
	DecoyRatio       float64 `yaml:"decoy_ratio"`
	EncryptionMethod string  `yaml:"encryption_method"`
}

// LoadFileConfig loads and processes a security-hardened configuration
func LoadFileConfig(filePath string) (*FileConfig, error) {
	manager, err := NewSecureConfigManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize secure config manager: %w", err)
	}
	
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
	}

	// Parse the obfuscated container structure
	var container SecureConfigContainer
	if err := yaml.Unmarshal(buf, &container); err != nil {
		// Try legacy format for backward compatibility
		var legacyContainer ConfigContainer
		if err := yaml.Unmarshal(buf, &legacyContainer); err != nil {
			return nil, fmt.Errorf("failed to parse config container: %w", err)
		}
		return manager.loadLegacyConfig(legacyContainer)
	}

	// Validate container integrity
	if err := manager.validateContainerIntegrity(&container); err != nil {
		return nil, fmt.Errorf("config integrity validation failed: %w", err)
	}

	var config FileConfig
	
	// Decrypt and deobfuscate configuration
	if container.ObfuscatedData != "" {
		decryptedData, err := manager.decryptAndDeobfuscate(container.ObfuscatedData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt configuration: %w", err)
		}
		
		if err := yaml.Unmarshal(decryptedData, &config); err != nil {
			return nil, fmt.Errorf("failed to parse decrypted config: %w", err)
		}
	} else {
		return nil, fmt.Errorf("only encrypted configurations are supported in secure mode")
	}

	// Generate polymorphic strategies
	polymorphicStrategies, err := manager.generatePolymorphicStrategies(config.Fingerprints)
	if err != nil {
		return nil, fmt.Errorf("failed to generate polymorphic strategies: %w", err)
	}
	config.Fingerprints = polymorphicStrategies

	// Inject decoy strategies
	decoyStrategies, err := manager.generateDecoyStrategies(len(config.Fingerprints))
	if err != nil {
		return nil, fmt.Errorf("failed to generate decoy strategies: %w", err)
	}
	config.Fingerprints = append(config.Fingerprints, decoyStrategies...)

	// Randomize strategy ordering
	if err := manager.randomizeStrategyOrder(&config); err != nil {
		return nil, fmt.Errorf("failed to randomize strategies: %w", err)
	}
	
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// decryptConfiguration decrypts the base64-encoded encrypted configuration
func decryptConfiguration(encryptedData string) ([]byte, error) {
	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}
	
	// Get decryption key (from secure source - environment, keychain, etc.)
	key := getConfigurationKey()
	if key == nil {
		return nil, fmt.Errorf("configuration decryption key not available")
	}
	
	// Decrypt using AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}
	
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return plaintext, nil
}

// getConfigurationKey retrieves the decryption key from a secure source
func getConfigurationKey() []byte {
	// Try environment variable first
	if keyStr := os.Getenv("GOCIRCUM_CONFIG_KEY"); keyStr != "" {
		hash := sha256.Sum256([]byte(keyStr))
		return hash[:]
	}
	
	// Try reading from secure key file
	if keyPath := os.Getenv("GOCIRCUM_KEY_PATH"); keyPath != "" {
		if keyData, err := os.ReadFile(keyPath); err == nil {
			hash := sha256.Sum256(keyData)
			return hash[:]
		}
	}
	
	// Fallback: development key (not for production)
	if isDevelopmentMode() {
		hash := sha256.Sum256([]byte("development-key-not-for-production"))
		return hash[:]
	}
	
	return nil
}

// isDevelopmentMode checks if we're running in development mode
func isDevelopmentMode() bool {
	return os.Getenv("GOCIRCUM_DEV_MODE") == "1" || 
		   strings.Contains(os.Args[0], "test") ||
		   os.Getenv("GO_ENV") == "development"
}

// filterRealStrategies separates real strategies from decoy strategies
func filterRealStrategies(strategies []Fingerprint, decoys []Fingerprint) []Fingerprint {
	// Create a map of decoy IDs for quick lookup
	decoyIDs := make(map[string]bool)
	for _, decoy := range decoys {
		decoyIDs[decoy.ID] = true
	}
	
	// Filter out decoy strategies
	var realStrategies []Fingerprint
	for _, strategy := range strategies {
		if !decoyIDs[strategy.ID] {
			realStrategies = append(realStrategies, strategy)
		}
	}
	
	return realStrategies
}

// LoadFingerprintsFromFile loads a list of fingerprints from a YAML file.
func LoadFingerprintsFromFile(filePath string) ([]Fingerprint, error) {
	config, err := LoadFileConfig(filePath)
	if err != nil {
		return nil, err
	}
	return config.Fingerprints, nil
}

// SecureConfigContainer replaces the simple ConfigContainer
type SecureConfigContainer struct {
	ObfuscatedData   string            `yaml:"data"`
	IntegrityHash    string            `yaml:"hash"`
	Metadata         ConfigMetadata    `yaml:"meta"`
	DecoyIndicators  []string          `yaml:"indicators,omitempty"`
	VersionInfo      string            `yaml:"version"`
}

// SecureConfigManager handles encrypted, obfuscated configuration with decoys
type SecureConfigManager struct {
	encryptionKey    []byte
	decoyGenerator   *DecoyStrategyGenerator
	strategyMutator  *StrategyPolymorphism
	configValidator  *ConfigValidator
}

// DecoyStrategyGenerator creates realistic but non-functional strategies
type DecoyStrategyGenerator struct {
	decoyTemplates       []DecoyTemplate
	randomizer           *SecureRandomizer
}

type StrategyPattern struct {
	CommonPorts       []int
	TLSVersions       []string
	FragmentSizes     [][2]int
	DelayRanges       [][2]int
	UserAgentPatterns []string
}

type DecoyTemplate struct {
	Description    string
	FrontDomain    string
	CovertTarget   string
	Protocol       string
	FragAlgorithm  string
	PacketSizes    [][2]int
	DelayMs        [2]int
	ClientHelloID  string
}

// StrategyPolymorphism dynamically modifies strategies to avoid fingerprinting
type StrategyPolymorphism struct {
	mutationRules map[string][]MutationRule
}

type MutationRule struct {
	Field      string
	Operation  string
	Parameters map[string]interface{}
}

type ConfigValidator struct {
	allowedDomains   map[string]bool
	securityPolicies map[string]SecurityPolicy
}

type SecurityPolicy struct {
	RequireEncryption bool
	AllowedTLSVersions []string
	RequiredHeaders    []string
}

type SecureRandomizer struct {
}

// NewSecureConfigManager creates a new secure configuration manager
func NewSecureConfigManager() (*SecureConfigManager, error) {
	return &SecureConfigManager{
		encryptionKey:   getConfigurationKey(),
		decoyGenerator:  NewDecoyStrategyGenerator(),
		strategyMutator: NewStrategyPolymorphism(),
		configValidator: NewConfigValidator(),
	}, nil
}

// NewDecoyStrategyGenerator creates a new decoy strategy generator
func NewDecoyStrategyGenerator() *DecoyStrategyGenerator {
	return &DecoyStrategyGenerator{
		decoyTemplates: createDecoyTemplates(),
		randomizer:     &SecureRandomizer{},
	}
}

// NewStrategyPolymorphism creates a new strategy polymorphism manager
func NewStrategyPolymorphism() *StrategyPolymorphism {
	return &StrategyPolymorphism{
		mutationRules: createMutationRules(),
	}
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		allowedDomains: createAllowedDomains(),
		securityPolicies: createSecurityPolicies(),
	}
}

// loadLegacyConfig handles backward compatibility with old config format
func (scm *SecureConfigManager) loadLegacyConfig(container ConfigContainer) (*FileConfig, error) {
	var config FileConfig
	
	if container.EncryptedConfig != "" {
		decryptedData, err := decryptConfiguration(container.EncryptedConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt legacy configuration: %w", err)
		}
		
		if err := yaml.Unmarshal(decryptedData, &config); err != nil {
			return nil, fmt.Errorf("failed to parse decrypted legacy config: %w", err)
		}
	} else {
		config = container.FileConfig
	}

	// Filter out decoy strategies if present
	if len(container.DecoyStrategies) > 0 {
		config.Fingerprints = filterRealStrategies(config.Fingerprints, container.DecoyStrategies)
	}
	
	return &config, nil
}

// validateContainerIntegrity ensures configuration hasn't been tampered with
func (scm *SecureConfigManager) validateContainerIntegrity(container *SecureConfigContainer) error {
	if container.IntegrityHash == "" {
		return fmt.Errorf("missing integrity hash")
	}
	
	// Calculate expected hash
	hash := sha256.Sum256([]byte(container.ObfuscatedData))
	expectedHash := fmt.Sprintf("%x", hash)
	
	if container.IntegrityHash != expectedHash {
		return fmt.Errorf("integrity validation failed - configuration may be tampered")
	}
	
	return nil
}

// decryptAndDeobfuscate decrypts and deobfuscates configuration data
func (scm *SecureConfigManager) decryptAndDeobfuscate(obfuscatedData string) ([]byte, error) {
	// First decode the obfuscation layer
	deobfuscated, err := scm.deobfuscateData(obfuscatedData)
	if err != nil {
		return nil, fmt.Errorf("deobfuscation failed: %w", err)
	}
	
	// Then decrypt the actual configuration
	return decryptConfiguration(deobfuscated)
}

// deobfuscateData removes obfuscation layer from configuration
func (scm *SecureConfigManager) deobfuscateData(data string) (string, error) {
	// Simple XOR-based deobfuscation with key rotation
	key := []byte("obfuscation-key-rotation-pattern")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	
	for i := range decoded {
		decoded[i] ^= key[i%len(key)]
	}
	
	return string(decoded), nil
}

// generatePolymorphicStrategies creates variations of base strategies
func (scm *SecureConfigManager) generatePolymorphicStrategies(baseStrategies []Fingerprint) ([]Fingerprint, error) {
	var polymorphic []Fingerprint
	
	for _, base := range baseStrategies {
		// Create 2-4 variations of each base strategy
		variantCount, _ := secureRandInt(2, 4)
		
		for i := 0; i < variantCount; i++ {
			variant, err := scm.strategyMutator.mutateStrategy(base, i)
			if err != nil {
				continue
			}
			polymorphic = append(polymorphic, variant)
		}
	}
	
	return polymorphic, nil
}

// mutateStrategy creates a functional variant of a base strategy
func (sp *StrategyPolymorphism) mutateStrategy(base Fingerprint, variant int) (Fingerprint, error) {
	mutated := base // Copy
	
	// Modify ID to be unique
	mutated.ID = fmt.Sprintf("%s_v%d_%x", base.ID, variant, time.Now().Unix()%1000)
	
	// Randomly mutate fragmentation parameters
	if mutated.Transport.Fragmentation != nil {
		sp.mutateFragmentation(mutated.Transport.Fragmentation)
	}
	
	// Randomly mutate TLS parameters
	sp.mutateTLS(&mutated.TLS)
	
	// Randomly mutate timing characteristics
	sp.mutateTimingCharacteristics(&mutated)
	
	return mutated, nil
}

// mutateFragmentation varies fragmentation parameters within safe ranges
func (sp *StrategyPolymorphism) mutateFragmentation(frag *Fragmentation) {
	// Vary packet sizes by ±20%
	for i := range frag.PacketSizes {
		for j := range frag.PacketSizes[i] {
			variation, _ := secureRandInt(-20, 20)
			newSize := frag.PacketSizes[i][j] + (frag.PacketSizes[i][j] * variation / 100)
			if newSize > 0 {
				frag.PacketSizes[i][j] = newSize
			}
		}
	}
	
	// Vary delays by ±30%
	for i := range frag.DelayMs {
		variation, _ := secureRandInt(-30, 30)
		newDelay := frag.DelayMs[i] + (frag.DelayMs[i] * variation / 100)
		if newDelay > 0 {
			frag.DelayMs[i] = newDelay
		}
	}
}

// mutateTLS modifies TLS parameters slightly
func (sp *StrategyPolymorphism) mutateTLS(tls *TLS) {
	// Rotate between similar TLS configurations
	alternatives := map[string][]string{
		"HelloChrome_Auto":  {"HelloChrome_58", "HelloChrome_62", "HelloChrome_70"},
		"HelloFirefox_Auto": {"HelloFirefox_55", "HelloFirefox_56", "HelloFirefox_63"},
		"HelloSafari_Auto":  {"HelloSafari_12_1", "HelloSafari_13"},
	}
	
	if alts, exists := alternatives[tls.ClientHelloID]; exists {
		idx, _ := secureRandInt(0, len(alts)-1)
		tls.ClientHelloID = alts[idx]
	}
}

// mutateTimingCharacteristics adjusts timing parameters
func (sp *StrategyPolymorphism) mutateTimingCharacteristics(fp *Fingerprint) {
	// Add small variations to delay ranges if fragmentation is configured
	if fp.Transport.Fragmentation != nil {
		// Small random adjustments to timing
		jitter, _ := secureRandInt(-5, 5)
		for i := range fp.Transport.Fragmentation.DelayMs {
			fp.Transport.Fragmentation.DelayMs[i] += jitter
			if fp.Transport.Fragmentation.DelayMs[i] < 0 {
				fp.Transport.Fragmentation.DelayMs[i] = 1
			}
		}
	}
}

// generateDecoyStrategies creates convincing fake strategies
func (scm *SecureConfigManager) generateDecoyStrategies(realCount int) ([]Fingerprint, error) {
	// Generate 2-5 decoy strategies to mix with real ones
	decoyCount, err := secureRandInt(2, 5)
	if err != nil {
		decoyCount = 3 // Fallback
	}
	
	var decoys []Fingerprint
	
	for i := 0; i < decoyCount; i++ {
		decoy, err := scm.decoyGenerator.generateSingleDecoy(i)
		if err != nil {
			continue // Skip failed decoys
		}
		decoys = append(decoys, decoy)
	}
	
	return decoys, nil
}

// generateSingleDecoy creates one realistic fake strategy
func (dsg *DecoyStrategyGenerator) generateSingleDecoy(index int) (Fingerprint, error) {
	// Create realistic but ineffective configuration
	templateIdx, _ := secureRandInt(0, len(dsg.decoyTemplates)-1)
	template := dsg.decoyTemplates[templateIdx]
	
	decoy := Fingerprint{
		ID:          fmt.Sprintf("decoy_%d_%x", index, time.Now().Unix()%1000),
		Description: template.Description,
		DomainFronting: &DomainFronting{
			Enabled:      true,
			FrontDomain:  template.FrontDomain,
			CovertTarget: template.CovertTarget,
		},
		Transport: Transport{
			Protocol: template.Protocol,
			Fragmentation: &Fragmentation{
				Algorithm:   template.FragAlgorithm,
				PacketSizes: template.PacketSizes,
				DelayMs:     template.DelayMs,
			},
		},
		TLS: TLS{
			Library:       "utls",
			ClientHelloID: template.ClientHelloID,
			MinVersion:    "1.2",
			MaxVersion:    "1.3",
		},
	}
	
	return decoy, nil
}

// randomizeStrategyOrder shuffles the strategy order to prevent patterns
func (scm *SecureConfigManager) randomizeStrategyOrder(config *FileConfig) error {
	strategies := config.Fingerprints
	
	// Cryptographically secure shuffle
	for i := len(strategies) - 1; i > 0; i-- {
		j, err := secureRandInt(0, i)
		if err != nil {
			return err
		}
		strategies[i], strategies[j] = strategies[j], strategies[i]
	}
	
	return nil
}

// Helper functions for creating templates and rules
func createDecoyTemplates() []DecoyTemplate {
	return []DecoyTemplate{
		{
			Description:   "Legacy Protocol Bridge",
			FrontDomain:   "legacy-api.cloudfront.net",
			CovertTarget:  "internal.legacy-system.com",
			Protocol:      "tcp",
			FragAlgorithm: "static",
			PacketSizes:   [][2]int{{100, 200}, {300, 400}},
			DelayMs:       [2]int{10, 50},
			ClientHelloID: "HelloChrome_58",
		},
		{
			Description:   "Mobile App Configuration",
			FrontDomain:   "config.mobile-cdn.net",
			CovertTarget:  "api.mobile-app.com",
			Protocol:      "tcp",
			FragAlgorithm: "even",
			PacketSizes:   [][2]int{{50, 100}},
			DelayMs:       [2]int{5, 25},
			ClientHelloID: "HelloAndroid_11_OkHttp",
		},
		{
			Description:   "Development Testing Framework",
			FrontDomain:   "test-assets.amazonaws.com",
			CovertTarget:  "dev.testing-framework.org",
			Protocol:      "tcp",
			FragAlgorithm: "static",
			PacketSizes:   [][2]int{{200, 300}, {150, 250}},
			DelayMs:       [2]int{15, 40},
			ClientHelloID: "HelloFirefox_55",
		},
	}
}

func createMutationRules() map[string][]MutationRule {
	return map[string][]MutationRule{
		"fragmentation": {
			{Field: "packet_sizes", Operation: "vary", Parameters: map[string]interface{}{"percentage": 20}},
			{Field: "delay_ms", Operation: "vary", Parameters: map[string]interface{}{"percentage": 30}},
		},
		"tls": {
			{Field: "client_hello_id", Operation: "rotate", Parameters: map[string]interface{}{"pool": "similar"}},
		},
	}
}

func createAllowedDomains() map[string]bool {
	return map[string]bool{
		"cloudfront.net":  true,
		"amazonaws.com":   true,
		"google.com":      true,
		"googleapis.com":  true,
		"gstatic.com":     true,
		"fastly.com":      true,
		"azureedge.net":   true,
	}
}

func createSecurityPolicies() map[string]SecurityPolicy {
	return map[string]SecurityPolicy{
		"default": {
			RequireEncryption:  true,
			AllowedTLSVersions: []string{"1.2", "1.3"},
			RequiredHeaders:    []string{"User-Agent", "Accept"},
		},
	}
}

// secureRandInt generates cryptographically secure random integers
func secureRandInt(min, max int) (int, error) {
	if min >= max {
		return min, nil
	}
	
	diff := max - min
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff+1)))
	if err != nil {
		return min, err
	}
	
	return min + int(n.Int64()), nil
}
