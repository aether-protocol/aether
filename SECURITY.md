# Security Policy

## Scope

This policy covers:
- Vulnerabilities in the Aether protocol specification (Parts 1–6)
- Vulnerabilities in the reference simulator (`sim/`)
- Vulnerabilities in the reference firmware (`firmware/`)
- Vulnerabilities in the host stacks (`host/`)

It does not cover third-party implementations of the Aether protocol. If you find a vulnerability in someone else's Aether implementation, contact them directly.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Send a report to: `security@aether-protocol.org` (placeholder — update before going public)

Your report should include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Which part of the spec or which component is affected
- Whether you believe this is exploitable in practice

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Disclosure timeline

- Day 0: Report received
- Day 2: Acknowledgement sent
- Day 7: Initial assessment — confirmed, investigating, or not a vulnerability
- Day 30: Fix developed (for confirmed vulnerabilities)
- Day 37: Fix reviewed by at least one external party
- Day 44: Fix released and public disclosure

We may extend the timeline for complex issues by mutual agreement. We will not extend it beyond 90 days from receipt without your explicit consent.

## Spec vulnerabilities vs implementation vulnerabilities

A *spec vulnerability* is a flaw in the protocol design — for example, a case where the handshake can be manipulated to bypass authentication regardless of how carefully it is implemented. These are more serious and may require an RFC to resolve.

An *implementation vulnerability* is a flaw in a specific codebase that a correct implementation of the spec would not have.

Please indicate in your report which type you believe you have found. We treat both seriously.

## Hall of fame

Researchers who responsibly disclose valid vulnerabilities will be credited here (with permission).
