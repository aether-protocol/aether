# Aether Protocol

**A clean-slate replacement for Bluetooth.**

Aether is an open wireless communication protocol for short-range device-to-device communication. It is designed from scratch to fix the problems that Bluetooth's 25-year-old architecture cannot — without breaking backwards compatibility as a constraint.

## Why Aether?

| Problem with Bluetooth | How Aether addresses it |
|---|---|
| Pairing state gets out of sync | No pairing state. Trust = key possession. |
| Security modes are a historical mess | One security model. Noise XX + AES-256-GCM. Always on. |
| Profile zoo (A2DP, HFP, GATT, SPP...) | One RPC mechanism. CBOR capability descriptors. |
| 3,000-page spec | Readable spec that fits in a single document. |
| Address spoofing trivial | Device address is derived from Ed25519 public key. |
| No forward secrecy by default | Ephemeral X25519 keys every session. Always. |
| Mesh bolted on after the fact | Mesh-first topology design (Part 4, in progress). |

## Status

> This is a working draft. The protocol is not yet stable. Breaking changes to the spec are expected.

| Part | Title | Status |
|---|---|---|
| Part 1 | Identity & Security Model | Draft |
| Part 2 | Link Layer & Frame Format | Draft |
| Part 3 | Service Layer | Draft |
| Part 4 | Mesh Routing | Not started |
| Part 5 | Group Sessions | Not started |
| Part 6 | Enterprise Extensions | Not started |

## Repository Layout

```
aether-protocol/
  spec/           Protocol specification (markdown)
  sim/            Software simulator (C#) — run the protocol without hardware
  firmware/       Controller firmware (C, targets Nordic nRF5340)
  host/           Host stack — Linux and Windows drivers
  sdk/            Developer SDKs (C# and C)
  docs/           Architecture decisions, RFCs, guides
    rfcs/         Formal design proposals
  tools/          Dev tooling (packet inspector, conformance tester)
```

## Getting Started

The fastest way to understand Aether is to read the spec and run the simulator.

**Read the spec:**
```
spec/SPEC-v0.1.md
```

**Run the simulator** (requires .NET 8+):
```bash
cd sim
dotnet run
```

The simulator spins up two virtual Aether nodes on localhost, performs the full handshake, and exchanges an encrypted RPC call. No hardware needed.

## Contributing

Aether is governed as an open standard. Contributions are welcome in four areas:

- **Spec changes** — open an RFC in `docs/rfcs/` using the template at `docs/rfcs/RFC-0000-template.md`
- **Simulator** — C# contributions under `sim/`
- **Firmware** — C contributions targeting nRF5340 under `firmware/`
- **New standard services** — propose additions to the service registry via RFC

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Design Principles

1. **Cryptographic identity by default.** Every device is its keypair.
2. **No persistent pairing state.** Stateless by design.
3. **Encryption is not optional.** There is no unencrypted mode.
4. **One framing for everything.** No per-service wire formats.
5. **The spec is the source of truth.** Code is a reference implementation, not the definition.
6. **Open governance.** No single company owns this.

## License

Specification: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — use it, implement it, build products with it.  
Code: [Apache 2.0](LICENSE)

## Contact

Open an issue or start a discussion on GitHub. There is no mailing list yet.
