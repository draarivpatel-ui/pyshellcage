# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes, once published |

## Reporting a vulnerability

Please do not open a public issue, pull request, or discussion for a suspected vulnerability.

Report it privately through the private security advisory form for this repository:

https://github.com/draarivpatel-ui/pyshellcage/security/advisories/new

Include a minimal reproducer, affected version, platform, Python version, and whether execution, validation, auditing, environment scrubbing, cwd containment, output bounding, or the CLI is affected.

If the issue involves a proof of concept, keep the payload benign. Do not include secrets, tokens, private paths, or real target infrastructure.

## Scope

In scope:

- Bypasses of the no-shell execution policy.
- Bypasses of executable allowlisting or shell/batch/symlink blocking.
- CWE-88 argument-validation or typed-builder confusion.
- Incorrect dangerous-flag detection with security impact.
- Environment denylist or allowlist bypasses.
- cwd realpath containment bypasses.
- Output cap, timeout, stdin, or UTF-8 truncation bypasses.
- CLI file-opening race or secret-value disclosure.

Out of scope:

- The inherent risk of executing an attacker controlled but explicitly allowlisted program.
- Application-level file authorization decisions.
- Vulnerabilities in the child program itself.
- Denial of service caused by inputs already inside the documented byte and count limits.
- Missing hardening that does not bypass a documented guarantee.

## Response expectations

Reports are acknowledged within 3 business days. Initial triage is targeted within 14 days. A fix, mitigation, or documented resolution is targeted within 90 days. Reporters are credited if they want credit. Do not disclose the issue publicly until a fix or coordinated advisory is available.
