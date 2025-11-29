# Security Policy

## Supported Versions

The following versions of Lucinda are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Supported Platforms

Security updates are provided for all supported target frameworks:

| Platform | Version | Status |
|----------|---------|--------|
| .NET | 10.0 | :white_check_mark: Supported |
| .NET | 9.0 | :white_check_mark: Supported |
| .NET | 8.0 LTS | :white_check_mark: Supported |
| .NET | 7.0 | :white_check_mark: Supported |
| .NET | 6.0 LTS | :white_check_mark: Supported |
| .NET Standard | 2.1 | :white_check_mark: Supported |
| .NET Standard | 2.0 | :white_check_mark: Supported |
| .NET Framework | 4.8.1 | :white_check_mark: Supported |
| .NET Framework | 4.8 | :white_check_mark: Supported |

## Reporting a Vulnerability

We take security vulnerabilities in Lucinda seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them using one of these methods:

1. **GitHub Security Advisory (Preferred)**
   - Go to the [Security tab](https://github.com/Taiizor/Lucinda/security)
   - Click "Report a vulnerability"
   - Fill out the security advisory form

2. **Private Disclosure**
   - If the above option is not available, please contact the maintainers directly through GitHub

### What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could potentially achieve
- **Affected Component**: Which part of Lucinda is affected (e.g., AES-GCM, RSA, ECDH, etc.)
- **Affected Versions**: Which versions are affected
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Proof of Concept**: If possible, include a minimal code sample demonstrating the vulnerability
- **Suggested Fix**: If you have ideas on how to fix the issue

### Example Report Format

```
## Summary
[Brief description of the vulnerability]

## Affected Component
- [ ] Symmetric Encryption (AES-GCM/AES-CBC)
- [ ] Asymmetric Encryption (RSA)
- [ ] Hybrid Encryption (RSA+AES)
- [ ] Key Derivation (PBKDF2/HKDF)
- [ ] Key Exchange (ECDH)
- [ ] Digital Signatures (ECDSA/RSA-PSS)
- [ ] Key Storage
- [ ] Other: [specify]

## Affected Versions
[e.g., All versions, 1.0.0 - 1.0.3, etc.]

## Impact
[What can an attacker do with this vulnerability?]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [...]

## Proof of Concept
```csharp
// Code demonstrating the vulnerability
```

## Suggested Fix
[If applicable]
```

### Response Timeline

- **Initial Response**: Within 48 hours of report submission
- **Status Update**: Within 7 days with an assessment of the vulnerability
- **Resolution Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 90 days

### After Reporting

1. You will receive an acknowledgment of your report within 48 hours
2. We will investigate and validate the vulnerability
3. We will work on a fix and coordinate disclosure timing with you
4. Once fixed, we will publicly acknowledge your contribution (unless you prefer to remain anonymous)

## Security Best Practices

When using Lucinda, please follow these security best practices:

### Key Management
- Never hardcode private keys or secrets in source code
- Use secure key storage mechanisms
- Rotate keys periodically
- Use separate keys for different purposes (encryption vs. signing)

### Algorithm Selection
- Use AES-GCM for authenticated encryption (preferred over AES-CBC)
- Use RSA keys of at least 2048 bits (3072+ recommended)
- Use ECDSA with P-256 or stronger curves
- Use PBKDF2 with at least 600,000 iterations for password-based key derivation

### Implementation
- Always validate `CryptoResult<T>.IsSuccess` before using values
- Use `using` statements or call `Dispose()` to ensure keys are cleared from memory
- Never log or expose plaintext keys or sensitive data
- Validate all inputs before passing to cryptographic functions

### Dependencies
- Keep Lucinda updated to the latest version
- Monitor security advisories for this library
- Use package vulnerability scanning in your CI/CD pipeline

## Cryptographic Standards

Lucinda follows these cryptographic standards and recommendations:

- **NIST SP 800-38D**: AES-GCM specification
- **NIST SP 800-56A**: Key establishment schemes
- **NIST SP 800-56B**: RSA-based key transport
- **NIST SP 800-132**: Password-based key derivation (PBKDF2)
- **RFC 5869**: HKDF specification
- **FIPS 186-4**: Digital Signature Standard (DSS)

## Acknowledgments

We would like to thank the following individuals for responsibly disclosing security issues:

*No security issues have been reported yet.*

---

Thank you for helping keep Lucinda and its users safe!