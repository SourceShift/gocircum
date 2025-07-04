package core

import (
	"time"
)

// GenerateDomainsForPeriod wraps the GetDomainsForPeriod method to maintain compatibility
func (dga *DomainGenerationAlgorithm) GenerateDomainsForPeriod(timePeriod time.Time, count int) ([]string, error) {
	return dga.GetDomainsForPeriod(timePeriod, count)
}
