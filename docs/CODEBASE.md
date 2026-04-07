# Aether Codebase Guide

This document explains what the Aether simulator codebase does and why — written for
someone new to the project and to applied cryptography.

---

## What Aether Is

Aether is a wireless communication protocol, like Bluetooth, but designed from scratch
with security as a first-class requirement. Every connection is encrypted, every device
has a cryptographic identity that cannot be forged, and keys are thrown away after each
session so old recordings cannot be decrypted later.

The code in this repository is the **reference simulator**: a complete C# implementation
of the Aether protocol stack, running in-process rather than over real radio hardware.
It proves the design works, provides test vectors for other implementations, and will be
the basis for porting to embedded C.

---

## Repository Layout

```
sim/src/
  Aether.Core/        — protocol library: all crypto, handshake, session, RPC
  Aether.Sim/         — console demo that exercises the full stack
  Aether.Tests/       — conformance tests (103 tests, all passing)

sdk/dotnet/
  AetherConnection.cs — async send/receive over an established session
  AetherClient.cs     — high-level entry point for applications

spec/SPEC-v0.1.md     — the authoritative protocol specification
docs/                 — RFCs, this document
```

---

## How the Pieces Fit Together

```
Application
    │
    ▼
AetherClient / AetherConnection    (sdk/dotnet/)
    │  async Send / Receive
    ▼
SessionChannel                     (Aether.Core)
    │  AES-256-GCM + replay counter
    ▼
HandshakeInitiator / Responder     (Aether.Core)
    │  Noise XX — 3-message mutual auth
    ▼
Crypto                             (Aether.Core)
    │  Ed25519, X25519, HKDF, SHA3-256, AES-GCM
    ▼
LinkLayer / LinkEndpoint           (Aether.Core)
    │  in-process byte-array queues (simulates radio)
    ▼
AetherNode                         (Aether.Core)
       owns keys, device ID, capability descriptor
```

Each layer has one job and knows nothing about the layers above it.

---

## Layer-by-Layer Explanation

### 1. `Crypto` — Building Blocks

**File:** [sim/src/Aether.Core/Crypto.cs](../sim/src/Aether.Core/Crypto.cs)

Every security property in the protocol ultimately rests on five primitives:

| Primitive | What it does | Why Aether uses it |
|---|---|---|
| **Ed25519** | Digital signatures | Proves a message came from a specific device; cannot be forged without the private key |
| **X25519** | Diffie-Hellman key exchange | Two devices compute the same secret without ever transmitting it |
| **HKDF-SHA256** | Key derivation | Turns a raw shared secret into properly formatted encryption keys |
| **AES-256-GCM** | Authenticated encryption | Encrypts data and detects any tampering |
| **SHA3-256** | Cryptographic hash | Produces a fixed-size fingerprint; used for device IDs and transcript hashing |

**Device ID:** `SHA3-256(Ed25519_public_key)[0:6]` — a 6-byte address derived from the
identity key. Changing the key means a different address; two devices cannot share an
address unless they share a key.

**Key formats:** Ed25519 keys are 32 bytes (private) / 32 bytes (public). X25519 keys
are also 32 bytes each. The private scalar must be "clamped" before use (three bit
manipulations required by RFC 7748); `Crypto.X25519KeyExchange` does this automatically
on a copy so the caller's data is never modified.

**Third-party libraries used:**
- `NSec.Cryptography` — Ed25519 sign/verify and X25519 key generation (safe, audited)
- `BouncyCastle.Cryptography` — raw X25519 DH output (NSec hides the shared secret
  behind an opaque handle; BouncyCastle exposes the raw bytes the handshake needs)
- .NET `AesGcm` — AES-256-GCM (hardware-accelerated on every modern CPU)

---

### 2. `AetherNode` — A Device's Identity

**File:** [sim/src/Aether.Core/AetherNode.cs](../sim/src/Aether.Core/AetherNode.cs)

An `AetherNode` represents one device. When constructed it generates and stores:

- **Ed25519 identity keypair** — the long-term identity; `IdentityPublicKey` is permanent
  and can be shown to the user ("this device is trusted")
- **X25519 static keypair** — used in the Diffie-Hellman steps of the handshake
- **DeviceId** — 6-byte address derived from the identity public key
- **BindingSig** — `Ed25519.sign(IdentityPrivateKey, StaticPublicKey)` — a cryptographic
  proof that the X25519 key belongs to this identity; verified by every peer during the
  handshake so the two key types cannot be mixed up or substituted

The node also holds a `CapabilityDescriptor` — a CBOR-encoded advertisement of what
services this device offers (see §6 below).

---

### 3. `LinkLayer` — Simulated Radio

**File:** [sim/src/Aether.Core/LinkLayer.cs](../sim/src/Aether.Core/LinkLayer.cs)

Real Aether devices communicate over a radio channel. In the simulator, two in-memory
queues take that role.

```
EndpointA ──write──► Channel A→B ──read──► EndpointB
EndpointA ◄──read──  Channel B→A ◄──write─ EndpointB
```

`LinkEndpoint.SendAsync` puts a byte array into the queue.
`LinkEndpoint.ReceiveAsync` waits until one arrives.

No serialization, no framing at this layer — just raw byte arrays passed between the
two sides. The layers above are responsible for the content.

---

### 4. `HandshakeInitiator` / `HandshakeResponder` — Noise XX

**File:** [sim/src/Aether.Core/Handshake.cs](../sim/src/Aether.Core/Handshake.cs)

The handshake establishes a shared secret between two devices that have never communicated
before, while simultaneously proving each side's identity. It uses the **Noise XX**
pattern, which is a published, peer-reviewed protocol framework.

#### Why three messages?

Symmetric encryption (AES-GCM) requires both sides to already share a key. Asymmetric
cryptography (Diffie-Hellman) can establish that key without prior contact, but raw DH
output is not suitable for encryption directly and does not prove identity. The handshake
solves both problems in three steps.

#### What happens in each message

**Message 1 — Initiator → Responder (34 bytes)**
```
[type=0x01 | flags=0x00 | ephemeral_pub (32 bytes)]
```
The initiator generates a one-time ("ephemeral") X25519 keypair and sends the public
half. Ephemeral keys are discarded after the session — this is what provides **forward
secrecy**: recording this message now is useless because the matching private key will
never exist again.

**Message 2 — Responder → Initiator (178 bytes)**
```
[type=0x02 | flags=0x00 | responder_ephemeral_pub (32) | encrypted_payload (144)]
```
The responder generates its own ephemeral keypair. Now both sides can compute:
- `k_ee = DH(e_I, e_R)` — a shared secret from the two ephemeral keys

The responder uses `k_ee` to AES-GCM-encrypt its **identity payload**:
`static_pub (32) ‖ identity_pub (32) ‖ binding_sig (64)` = 128 bytes + 16-byte tag = 144.

The **AAD** (additional authenticated data) fed to AES-GCM is `SHA3-256(msg1 ‖ msg2_prefix)` —
a hash of everything transmitted so far. This means the tag covers the transcript, so
any replayed or reordered message will fail authentication.

**Message 3 — Initiator → Responder (146 bytes)**
```
[type=0x03 | flags=0x00 | encrypted_payload (144)]
```
The initiator decrypts msg2, verifies the binding signature (`Ed25519.verify(identity_pub,
static_pub, binding_sig)`), and now knows the responder's identity.

It then computes two more DH operations:
- `k_es = DH(e_I, s_R)` — ephemeral-static: proves the responder owns its static key
- `k_se = DH(s_I, e_R)` — static-ephemeral: proves the initiator owns its static key

The msg3 encryption key is derived from `k_ee` and `k_es` via HKDF. The initiator sends
its own identity payload encrypted with this key.

#### After message 3

The responder decrypts msg3, verifies the initiator's binding signature, and both sides
now independently compute session key material from HKDF:

```
input = k_ee ‖ k_se
salt  = SHA3-256(msg1 ‖ msg2 ‖ msg3)    ← full transcript hash
output (76 bytes):
  [0:32]  I→R encryption key
  [32:64] R→I encryption key
  [64:76] 12-byte nonce IV (shared)
```

The transcript hash in the salt means the derived keys are unique to this exact exchange;
an attacker who modifies any bit of any message gets different keys and cannot communicate.

Both sides expose `SessionKeyToSend`, `SessionKeyToReceive`, and `SessionNonceIV` after
the handshake completes.

---

### 5. `SessionChannel` — Encrypted Data Channel

**File:** [sim/src/Aether.Core/SessionChannel.cs](../sim/src/Aether.Core/SessionChannel.cs)

After the handshake, all data is exchanged through `SessionChannel`. One instance covers
one direction (I→R or R→I), so each connection has two.

**Frame layout:**
```
[counter (8 bytes, little-endian) | ciphertext | GCM tag (16 bytes)]
```

**Nonce construction:** AES-GCM requires a unique 12-byte nonce for every message
encrypted with the same key. The spec's approach:

```
nonce = fixed_iv XOR encode64(counter)
```

`fixed_iv` is the 12-byte nonce IV from the handshake (shared by both sides).
`encode64(counter)` is the 8-byte little-endian counter, zero-padded to 12 bytes.
The XOR ensures each frame gets a different nonce while both sides can reconstruct it
independently without any extra communication.

**Authentication:** The 8-byte counter header is passed as AAD to AES-GCM. This means
the tag covers the counter — tampering with the counter field in transit is detected.

**Replay protection:** The receiver tracks the last accepted counter. Any incoming frame
whose counter is ≤ the last accepted value throws `CryptographicException`. This prevents
an attacker from recording and re-sending a legitimate frame.

---

### 6. `CapabilityDescriptor` — Service Advertisement

**File:** [sim/src/Aether.Core/CapabilityDescriptor.cs](../sim/src/Aether.Core/CapabilityDescriptor.cs)

Before or after connecting, a device can advertise what services it offers using a
**CBOR**-encoded capability descriptor. CBOR (Concise Binary Object Representation) is
like a binary version of JSON — compact enough to fit in small radio packets.

The descriptor contains:
- **DeviceInfo** — human-readable name, software/hardware version, manufacturer
- **CryptoCapabilities** — MTU, whether ChaCha20-Poly1305 is supported, delayed-ack mode
- **Services** — list of services, each with a 16-byte UUID, version, methods (call → return),
  and events (push notifications)

`ToCborBytes()` serializes to bytes; `FromCbor(byte[])` deserializes back.

---

### 7. `ServiceLayer` — Remote Procedure Calls

**File:** [sim/src/Aether.Core/ServiceLayer.cs](../sim/src/Aether.Core/ServiceLayer.cs)

The service layer implements RPC (Remote Procedure Calls) — the mechanism by which one
device asks another to do something and receives a result. Aether uses a single unified
RPC system rather than Bluetooth's collection of separate profiles (A2DP, HFP, etc.).

**RPC frame layout (Spec Part 3 §6):**
```
[service_id (16 bytes) | method_id (1 byte) | call_id (2 bytes BE) | flags (1 byte) | CBOR args]
```

- `service_id` — UUID of the service (e.g. Temperature)
- `method_id` — which method to call within that service
- `call_id` — echo'd back in the response so the caller can match replies
- `flags` — bit 0: response expected; bit 1: this is a response; bit 2: this is an event
- CBOR args — method-specific arguments encoded as a CBOR map

`RegisterHandler(serviceId, methodId, handler)` installs a handler function.
`ProcessRpcFrame(frame)` dispatches an incoming request and returns the response bytes,
or `null` for fire-and-forget messages and events.

---

### 8. `AetherConnection` / `AetherClient` — High-Level SDK

**Files:**
- [sdk/dotnet/AetherConnection.cs](../sdk/dotnet/AetherConnection.cs)
- [sdk/dotnet/AetherClient.cs](../sdk/dotnet/AetherClient.cs)

These are the application-facing API. `AetherConnection` wires together the handshake
and session channel:

```csharp
// Inside RunAsInitiatorAsync:
msg1 = hs.Step()          // build msg1
await send(msg1)
msg2 = await receive()
msg3 = hs.Step(msg2)      // process msg2 → produces msg3 and session keys
await send(msg3)
// Now _txChannel and _rxChannel are live
```

`SendAsync(plaintext)` → `SessionChannel.Encrypt` → `LinkEndpoint.SendAsync`
`ReceiveAsync()` → `LinkEndpoint.ReceiveAsync` → `SessionChannel.Decrypt`

`AetherClient.CreateSimulatedPairAsync` is a convenience helper that creates two nodes,
one link layer, and runs both sides of the handshake concurrently — useful for tests and
the demo.

---

## The Demo (`Program.cs`)

**File:** [sim/src/Aether.Sim/Program.cs](../sim/src/Aether.Sim/Program.cs)

The console demo exercises the entire stack end-to-end:
1. Creates two `AetherNode` instances
2. Runs the three-message handshake, printing each message's hex bytes
3. Verifies both sides derived the same session keys
4. Registers a Temperature service handler on node B
5. Node A sends a `Temperature.read` RPC call; node B decodes it, executes the handler,
   and responds with temperature 21500 m°C; node A prints the decoded result

---

## The Tests (`Aether.Tests/`)

103 xUnit tests across four files:

| File | What it tests |
|---|---|
| [CryptoTests.cs](../sim/src/Aether.Tests/CryptoTests.cs) | SHA3-256 (NIST FIPS 202 vectors), HKDF-SHA256 (RFC 5869 vectors), AES-GCM (NIST SP 800-38D), X25519 symmetry, Ed25519 sign/verify |
| [HandshakeTests.cs](../sim/src/Aether.Tests/HandshakeTests.cs) | Session key agreement, wire message sizes, identity verification, tamper detection |
| [SessionChannelTests.cs](../sim/src/Aether.Tests/SessionChannelTests.cs) | Nonce construction, frame layout, round-trip encryption, replay protection |
| [RpcTests.cs](../sim/src/Aether.Tests/RpcTests.cs) | RPC frame parsing, method dispatch, error responses, call ID echo |
| [CapabilityDescriptorTests.cs](../sim/src/Aether.Tests/CapabilityDescriptorTests.cs) | CBOR round-trips for every field, size budget |

Tests that use fixed known inputs (RFC/NIST vectors) prove the implementation matches
the published reference. Tests that use generated keys prove the protocol properties
(symmetry, tamper detection, replay rejection) hold for any inputs.

---

## Security Properties Provided

| Property | How it's achieved |
|---|---|
| **Confidentiality** | All data encrypted with AES-256-GCM |
| **Integrity** | GCM authentication tag detects any modification |
| **Mutual authentication** | Both devices verify each other's binding signature during handshake |
| **Forward secrecy** | Ephemeral X25519 keys discarded after the session; past sessions cannot be decrypted |
| **Replay protection** | Monotone counter enforced on every received frame |
| **Identity binding** | Ed25519 signature ties the DH static key to the long-term identity |

---

## Running the Code

```bash
# Build and test everything
cd sim
dotnet build
dotnet test

# Run the end-to-end demo
cd sim/src/Aether.Sim
dotnet run

# Run a single test
dotnet test --filter "FullyQualifiedName~HandshakeTests.Handshake_BothSides_DeriveIdenticalSendReceiveKeys"
```
