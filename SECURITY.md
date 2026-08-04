# Security Policy

scopuli is a credential vault — security reports are taken seriously and handled privately.

## Supported Versions

Only the **latest release** receives security fixes. There is no backport policy while the project is pre-1.0.

| Version | Supported |
|---|---|
| latest release | yes |
| anything older | no — upgrade first |

## Reporting a Vulnerability

**Do not open a public issue for a vulnerability.**

Report privately via [GitHub Security Advisories](https://github.com/lucaspdude/scopuli/security/advisories/new).

Please include:

- A description of the issue and its impact (what an attacker gains).
- Steps to reproduce or a proof of concept.
- Affected version(s) and deployment setup (local / VPS, behind TLS or not).

You can expect:

- Acknowledgement within a few days (solo maintainer, best effort).
- A fix or mitigation plan before any public disclosure.
- Credit in the release notes, unless you prefer to stay anonymous.

## Scope notes

Before reporting, please check the threat model summary on the
[docs site](https://lucaspdude.github.io/scopuli/security/). Some scenarios are
explicitly out of scope for the current design — for example:

- Reading process memory of a running vault (KEK lives in RAM by design).
- Root compromise of the host/container (that is the stated trust boundary).
- Exposing the port without TLS — the server does not terminate TLS; a reverse proxy is mandatory for non-localhost deployments (documented, not a bug).

Issues that break the documented guarantees — scope enforcement, encryption at rest, audit-chain integrity, token/key handling — are always in scope.
