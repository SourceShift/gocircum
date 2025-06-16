package config

import (
	"fmt"
	"gocircum/core/constants"
	"sort"
	"strings"
)

func (fc *FileConfig) Validate() error {
	if len(fc.Fingerprints) == 0 {
		return fmt.Errorf("no fingerprints found in configuration")
	}

	for i, fp := range fc.Fingerprints {
		if fp.ID == "" {
			return fmt.Errorf("fingerprint %d is missing an id", i)
		}
		if fp.Transport.Protocol != "tcp" && fp.Transport.Protocol != "quic" {
			return fmt.Errorf("fingerprint '%s' has an invalid transport protocol: %s", fp.ID, fp.Transport.Protocol)
		}
		if fp.TLS.Library != "stdlib" && fp.TLS.Library != "go-stdlib" && fp.TLS.Library != "utls" && fp.TLS.Library != "uquic" {
			return fmt.Errorf("fingerprint '%s' has an invalid TLS library: %s", fp.ID, fp.TLS.Library)
		}
		if fp.TLS.ClientHelloID == "" && (fp.TLS.Library == "utls" || fp.TLS.Library == "uquic") {
			return fmt.Errorf("fingerprint '%s' is missing a client_hello_id for utls/uquic", fp.ID)
		}
		if fp.TLS.MinVersion != "" {
			if _, ok := constants.TLSVersionMap[fp.TLS.MinVersion]; !ok {
				return fmt.Errorf("invalid TLS MinVersion '%s' for fingerprint '%s'. Supported versions are: %s", fp.TLS.MinVersion, fp.ID, getSupportedTLSVersions())
			}
		}
		if fp.TLS.MaxVersion != "" {
			if _, ok := constants.TLSVersionMap[fp.TLS.MaxVersion]; !ok {
				return fmt.Errorf("invalid TLS MaxVersion '%s' for fingerprint '%s'. Supported versions are: %s", fp.TLS.MaxVersion, fp.ID, getSupportedTLSVersions())
			}
		}
	}
	return nil
}

func getSupportedTLSVersions() string {
	versions := make([]string, 0, len(constants.TLSVersionMap))
	for v := range constants.TLSVersionMap {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return strings.Join(versions, ", ")
}
