# Secure Random Number Generation Guidelines

## Introduction

Proper random number generation is critical for security in the GoCircum framework. Weak or predictable random numbers can compromise the security of various features including:

- Cryptographic operations
- Security protocol implementations
- Network communications
- Authentication and authorization
- Timing and jitter calculations in security-critical paths

## Rules

1. **Ban on `math/rand`**: The use of `math/rand` package is strictly prohibited in security-critical code. 
    - The Go standard library's `math/rand` package uses a deterministic algorithm that is NOT cryptographically secure.
    - Even with seeding from a secure source, `math/rand` remains unsuitable for security purposes.

2. **Secure Alternatives**: Always use one of the following secure alternatives:
    - `crypto/rand` from the Go standard library for raw randomness
    - `pkg/securerandom` package from GoCircum, which provides higher-level abstractions with proper error handling

3. **Error Handling**: All calls to random number generators MUST check for and handle errors appropriately.
    - Security-critical code must fail securely when randomness cannot be generated
    - Fallbacks to deterministic sources are strictly prohibited

4. **Testing Considerations**: 
    - Test code may use `math/rand` for deterministic tests if needed
    - Such code must be clearly isolated in test files
    - Mocked randomness should never be used in production code paths

## Using the `securerandom` Package

The `pkg/securerandom` package provides several functions for common randomness needs:

```go
// Generate random integer in range [min, max]
num, err := securerandom.Int(1, 100)
if err != nil {
    // Handle error properly - never ignore!
    return err
}

// Generate random float in range [0.0, 1.0)
float, err := securerandom.Float64()
if err != nil {
    return err
}

// Generate random bytes
bytes := make([]byte, 32)
if err := securerandom.Bytes(bytes); err != nil {
    return err
}

// Generate random duration for jitter
duration, err := securerandom.Duration(100*time.Millisecond, 500*time.Millisecond)
if err != nil {
    return err
}

// Shuffle a slice securely
items := []string{"a", "b", "c", "d"}
err := securerandom.Shuffle(items, func(i, j int) {
    items[i], items[j] = items[j], items[i]
})
if err != nil {
    return err
}
```

## Static Analysis Enforcement

GoCircum enforces these rules through static analysis:

1. A custom linter (`mathrandom-linter`) automatically checks for `math/rand` imports
2. CI/CD pipelines will fail if improper usage is detected
3. Pre-commit hooks prevent accidental introduction of insecure RNG
4. Limited exemptions exist for specific non-security-critical cases, with expiration dates

## Requesting Exemptions

In rare cases where `math/rand` must be used in non-security-critical code:

1. File an issue in the security tracker explaining the use case
2. Document why `crypto/rand` or `securerandom` cannot be used
3. Clearly define the scope and impact
4. Include a timeline for migration to secure alternatives

Exemptions are tracked in `configs/mathrandom-exempt.json` and are subject to periodic review.

## Examples

### ❌ Incorrect Usage (FORBIDDEN)

```go
import (
    "math/rand"
    "time"
)

func generateToken() string {
    // WRONG: Using math/rand, even with time-based seeding
    rand.Seed(time.Now().UnixNano())
    // ... token generation using math/rand
}
```

### ✅ Correct Usage

```go
import (
    "github.com/gocircum/gocircum/pkg/securerandom"
)

func generateToken() (string, error) {
    // CORRECT: Using the securerandom package with error handling
    // ... token generation using securerandom
    // ... with proper error handling
}
```

## Further Reading

- [NIST SP 800-90A Rev. 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf): Recommendation for Random Number Generation
- [Go Security Policy](https://go.dev/security/policy)
- [GoCircum Security Principles](../security-principles.md)
