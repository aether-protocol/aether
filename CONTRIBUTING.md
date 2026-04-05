# Contributing to Aether

Thank you for your interest in contributing. This document explains how the project is governed and how to get involved.

## Types of contribution

### Spec changes (RFCs)

Any change to the protocol specification — including new features, behaviour clarifications, and breaking changes — must go through the RFC process.

1. Copy `docs/rfcs/RFC-0000-template.md` to `docs/rfcs/RFC-NNNN-short-title.md` where NNNN is the next available number.
2. Fill in the template. The most important sections are "Motivation" (why is the current spec wrong or incomplete?) and "Alternatives considered" (what else did you think about?).
3. Open a pull request. The PR title should be `RFC NNNN: Short title`.
4. A two-week comment period begins. Anyone may comment.
5. Two maintainer approvals are required to merge.
6. Merged RFCs are binding — the spec is updated to match.

Breaking changes to Part 1 (security model) require an additional one-week waiting period after the two maintainer approvals, to allow for broader security review.

### Simulator contributions (C#)

The simulator lives in `sim/`. It requires .NET 8 or later.

```bash
cd sim
dotnet build
dotnet test
```

All simulator contributions must include tests. Tests live in `sim/tests/`. The test suite is the conformance suite — if the simulator passes all tests, it is a correct implementation of the spec.

### Firmware contributions (C)

The firmware lives in `firmware/` and targets the Nordic nRF5340-DK development board. It requires the Zephyr RTOS SDK.

See `firmware/README.md` for setup instructions.

### SDK contributions

SDKs live in `sdk/dotnet/` (C#) and `sdk/c/` (C99). The C# SDK wraps the simulator for host-side development. The C SDK is intended for embedding in applications that use the Linux host stack.

### New standard services

Proposing a new standard service UUID requires an RFC. The RFC must include the full service descriptor (in the CBOR schema format defined in Part 3), at least one worked example of a method call and response in hex, and a rationale for why this should be a standard service rather than a vendor service.

## Code style

**C#:** Follow the .NET runtime coding conventions. Use `dotnet format` before committing.

**C:** C99, `clang-format` with the style file at `.clang-format`. No dynamic allocation in firmware code.

**Markdown:** One sentence per line (makes diffs readable). No line length limit.

## Commit messages

Use the conventional commits format:

```
type(scope): short description

Longer explanation if needed. Wrap at 72 characters.

Refs: #issue-number
```

Types: `feat`, `fix`, `spec`, `docs`, `test`, `chore`  
Scopes: `spec`, `sim`, `firmware`, `sdk`, `rfc`

Example: `spec(part2): add DoS considerations section`

## Governance

The project is currently maintained by its founder. The intent is to move to a multi-maintainer model as the community grows. Maintainer status is granted by consensus of existing maintainers after sustained, high-quality contribution.

There is no Contributor License Agreement. Contributions are accepted under the repository's Apache 2.0 license (code) or CC BY 4.0 (spec). By opening a pull request you confirm that you have the right to license your contribution under these terms.

## Code of conduct

Be direct. Be specific. Assume good faith. Do not make it personal.

Technical disagreements belong in the RFC comment thread, not in issue trackers or commit messages.
