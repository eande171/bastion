# Security Policy

## Supported Versions
As Bastion exists solely as an API and all updates are immediately deployed, only the current version is supported for updates.

## Reporting a Vulnerability
If you believe you've found a security vulnerability in Bastion, please report it responsibly using GitHub's private vulnerability reporting. You can find this under the [Security](https://github.com/eande171/bastion/security) tab of this repository.
Please don't open a public issue for security vulnerabilities or disclose any information publicly until a fix is available. Private reporting keeps things safe for everyone while we work on a fix.

## What to Include
To help us understand and reproduce the issue, try to include:
- A description of the vulnerability and its potential impact
- Steps to reproduce it
- Any relevant request/response examples (with sensitive data removed)

## Scope
The following are considered in scope:
- The Bastion API (`bastion.eande171.workers.dev`)
- Authentication and key handling
- Any unintended exposure of user-submitted data

The following are **out of scope**:
- The demo UI appearance or UX issues
- Rate limiting behaviour that doesn't result in data exposure
- Vulnerabilities in third-party services Bastion depends on (Cloudflare, HaveIBeenPwned), though reports regarding **misconfigurations** of these services within Bastion are welcome.

## Response
Bastion is a solo project, so I'll do my best to respond to reports in a timely manner. I'll aim to acknowledge reports within a week and keep you updated as things progress.
If a fix is issued as a result of your report, I'm happy to credit you in the release notes! Just let me know if you'd prefer to stay anonymous.

## A Note on Bastion's Design
Raw passwords submitted to the API are never stored or logged. Breach checking is performed using k-anonymity (this requires SHA-1), meaning only a partial hash prefix is ever sent to HaveIBeenPwned. Your full password hash never leaves Bastion.
