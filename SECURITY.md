# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Only the latest release line receives security updates.

## Reporting a vulnerability

Please report vulnerabilities through GitHub private vulnerability reporting:

- https://github.com/hacksurvivor/ai-sec/security/advisories/new

If the private reporting form is unavailable, open a public issue with only:

- high-level impact summary
- affected component path(s)
- request for a private follow-up channel

Do not post exploit details, proof-of-concept payloads, or secrets in public issues.

## What to include in a report

- affected version/tag and deployment mode (`mock`, `ollama`, etc.)
- exact API path or CLI workflow
- reproducible steps
- expected vs actual behavior
- impact (data exposure, auth bypass, command execution, denial of service)
- suggested fix, if available

## Response targets

- Initial triage target: within 3 business days.
- Status update target: every 7 calendar days until resolution.
- Fix target: best effort based on severity and exploitability.

## Scope

In scope:

- gateway auth/authorization bypasses
- prompt injection bypasses that evade declared controls
- data leakage across users/sessions
- release artifact integrity issues

Out of scope:

- social engineering or phishing attempts
- vulnerabilities requiring local machine compromise first
- denial-of-service from clearly unrealistic traffic volumes
