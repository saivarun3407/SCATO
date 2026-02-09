# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Reporting a Vulnerability

We take security seriously at SCATO. If you discover a security vulnerability, please follow these steps:

### 1. Do NOT Create a Public Issue

Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.

### 2. Report Privately

Send a detailed report to: **security@scato.dev** (or create a private security advisory on GitHub)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 3. Response Timeline

| Action | Timeframe |
|--------|-----------|
| Initial acknowledgment | 48 hours |
| Preliminary assessment | 7 days |
| Fix development | 30 days (for critical issues) |
| Public disclosure | After fix is released |

## Security Best Practices

### For Users

1. **Keep SCATO Updated**: Always use the latest version
2. **Protect API Keys**: Never commit NVD or GitHub tokens to version control
3. **Use Environment Variables**: Store secrets in `.env` files (not `.env.example`)
4. **Review Policies**: Customize `.scato-policy.json` for your security requirements
5. **Enable CI/CD Integration**: Automate scanning on every commit

### For Developers

1. **Dependencies**: Run SCATO on SCATO regularly to catch vulnerabilities in our own dependencies
2. **Input Validation**: All user inputs are validated before processing
3. **No Eval**: Never use `eval()` or similar dynamic code execution
4. **Secure Defaults**: Security-focused defaults in all configurations

## Security Features

SCATO includes several security features:

- **Multi-Source Vulnerability Data**: OSV, NVD, GHSA, CISA KEV, EPSS
- **Policy Enforcement**: Configurable security policies
- **SBOM Generation**: CycloneDX and SPDX formats
- **License Detection**: Flags copyleft and unknown licenses
- **SARIF Output**: Integration with security dashboards

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities:

- (This space reserved for security contributors)

## Contact

For security inquiries: security@scato.dev

For general questions: Open a GitHub issue
