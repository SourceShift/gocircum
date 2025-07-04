package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTLSValidate(t *testing.T) {
	tests := []struct {
		name        string
		yamlConfig  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Empty_TLS_Config",
			yamlConfig:  "{}",
			expectError: false,
		},
		{
			name: "Valid_Config",
			yamlConfig: `
library: "utls"
client_hello_id: "chrome"
`,
			expectError: false,
		},
		{
			name: "Invalid_Library",
			yamlConfig: `
library: "unsupported"
client_hello_id: "chrome"
`,
			expectError: true,
			errorMsg:    "security policy violation: tls.library must be 'utls'",
		},
		{
			name: "Missing_ClientHelloID",
			yamlConfig: `
library: "utls"
`,
			expectError: true,
			errorMsg:    "tls.client_hello_id must be specified",
		},
		{
			name: "InsecureSkipVerify_Attempted",
			yamlConfig: `
library: "utls"
client_hello_id: "chrome"
insecure_skip_verify: true
`,
			expectError: true,
			errorMsg:    "security policy violation: certificate validation bypassing (insecure_skip_verify) is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tlsConfig TLS
			err := yaml.Unmarshal([]byte(tt.yamlConfig), &tlsConfig)

			if tt.expectError {
				if err == nil {
					// Try validation if unmarshaling succeeded
					err = tlsConfig.Validate()
				}

				if err == nil {
					t.Errorf("expected error containing %q, but got no error", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, but got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Validate if we expect no error
				if err = tlsConfig.Validate(); err != nil {
					t.Errorf("unexpected validation error: %v", err)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return s != "" && substr != "" && strings.Contains(s, substr)
}
