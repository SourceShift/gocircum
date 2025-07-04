package doh

import (
	"testing"
)

func TestSecureRandomIndex(t *testing.T) {
	testCases := []struct {
		name    string
		max     int
		wantErr bool
	}{
		{
			name:    "valid max",
			max:     10,
			wantErr: false,
		},
		{
			name:    "zero max",
			max:     0,
			wantErr: false,
		},
		{
			name:    "negative max",
			max:     -5,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := secureRandomIndex(tc.max)

			if (err != nil) != tc.wantErr {
				t.Errorf("secureRandomIndex(%d) error = %v, wantErr %v", tc.max, err, tc.wantErr)
				return
			}

			if tc.max <= 0 {
				if idx != 0 {
					t.Errorf("secureRandomIndex(%d) = %d, want 0", tc.max, idx)
				}
			} else {
				if idx < 0 || idx >= tc.max {
					t.Errorf("secureRandomIndex(%d) = %d, want value between 0 and %d", tc.max, idx, tc.max-1)
				}
			}
		})
	}
}

func TestGetShuffledProviders(t *testing.T) {
	// Create a provider with some test providers
	p := &Provider{
		providers: []string{"provider1", "provider2", "provider3", "provider4", "provider5"},
		logger:    nil, // We don't need logging for this test
	}

	// Get shuffled providers
	shuffled := p.getShuffledProviders()

	// Verify the length is the same
	if len(shuffled) != len(p.providers) {
		t.Errorf("getShuffledProviders() returned %d providers, want %d", len(shuffled), len(p.providers))
	}

	// Verify all providers are present
	providerMap := make(map[string]bool)
	for _, provider := range p.providers {
		providerMap[provider] = true
	}

	for _, provider := range shuffled {
		if !providerMap[provider] {
			t.Errorf("getShuffledProviders() returned unknown provider: %s", provider)
		}
	}
}

func TestCryptoShuffle(t *testing.T) {
	// Create a provider
	p := &Provider{
		logger: nil, // We don't need logging for this test
	}

	// Create a test slice
	original := []string{"item1", "item2", "item3", "item4", "item5"}
	testSlice := make([]string, len(original))
	copy(testSlice, original)

	// Shuffle the slice
	p.cryptoShuffle(testSlice)

	// Verify the length is the same
	if len(testSlice) != len(original) {
		t.Errorf("cryptoShuffle() resulted in slice of length %d, want %d", len(testSlice), len(original))
	}

	// Verify all items are present
	itemMap := make(map[string]bool)
	for _, item := range original {
		itemMap[item] = true
	}

	for _, item := range testSlice {
		if !itemMap[item] {
			t.Errorf("cryptoShuffle() resulted in unknown item: %s", item)
		}
	}
}
