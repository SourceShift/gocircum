fix(security): Harden DoH client and patch critical vulnerabilities

This commit addresses critical security vulnerabilities identified in a threat report, focusing on DNS-over-HTTPS (DoH) communications and Server Name Indication (SNI) leaks.

### DoH Domain Fronting

To prevent adversaries from blocking or fingerprinting DoH traffic, the DoH client has been hardened to use domain fronting.

- The `DoHProvider` configuration in `core/config/types.go` is extended with a `FrontDomain` field.
- The DoH client in `core/proxy/doh.go` now uses this `FrontDomain` for the TLS SNI, while sending the actual DoH provider's hostname in the encrypted `Host` header. This masks the true destination from network observers.

### Regression Fix: DoH `Host` Header

An initial implementation of the domain fronting logic introduced a regression causing `403 Forbidden` errors from DoH providers when not using a front domain.

- The logic in `core/proxy/doh.go` was corrected to ensure the `Host` header is always set to the `provider.ServerName`. This is required for both direct and domain-fronted requests and resolves the failing tests.

### SNI Leak in Strategy Testing

The threat report also identified a critical SNI leak in the strategy ranker (`core/ranker/ranker.go`), where an IP address was being used as the SNI. Investigation confirmed that this vulnerability had already been patched in a previous commit by creating a temporary TLS config with the correct hostname for testing. No changes were required for this issue.

These changes significantly improve the application's resistance to censorship and surveillance by protecting its critical internal DNS resolution mechanism. 