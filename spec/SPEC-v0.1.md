# Aether Protocol Specification
## Part 1: Identity & Security Model
**Version:** 0.1-draft  
**Status:** Working Draft  
**Authors:** TBD  

---

## 1. Introduction

Aether is a short-range wireless communication protocol designed as a clean-slate replacement for Bluetooth. It prioritises:

- Cryptographic identity by default — no concept of "pairing ceremonies"
- Minimal persistent state — devices do not need to remember each other to communicate securely
- Modern authenticated encryption throughout
- A clear, auditable security model that fits in a single document

This part of the specification defines how devices identify themselves, how sessions are established, and how all data is encrypted and authenticated.

---

## 2. Design Principles

### 2.1 Identity is a keypair

Every Aether device has exactly one long-term identity: an Ed25519 keypair. There is no separate "address" assigned by infrastructure. The device's address on the network is derived directly from its public key.

This means:
- Device addresses are globally unique by construction
- Spoofing an address requires compromising the corresponding private key
- No central authority or address allocation is needed

### 2.2 No pairing state

Bluetooth's "pairing" creates persistent bonding state on both devices, which must stay in sync. When it drifts out of sync (one device forgets, a factory reset occurs, etc.), the result is confusing user-facing failures.

Aether has no pairing concept. Trust between two devices is established by one device knowing the other's public key. How that public key is obtained is out-of-band (QR code, NFC tap, manual entry, a trust-on-first-use policy, or a higher-level application layer). The protocol itself only asks: "do you have my public key?"

### 2.3 Every session is fresh

Session keys are never reused across connections. Each new connection performs a full key exchange. This provides forward secrecy: compromising a device's long-term private key does not expose past session traffic.

### 2.4 Encryption is not optional

There is no "unencrypted mode" in Aether. All data frames after the handshake are encrypted and authenticated. A device that cannot complete the handshake cannot participate in the network.

---

## 3. Cryptographic Primitives

Aether uses a small, conservative set of well-audited primitives. All are from the libsodium / NaCl family.

| Purpose                  | Primitive              | Notes |
|--------------------------|------------------------|-------|
| Long-term identity       | Ed25519                | 256-bit, fast sign/verify on constrained hardware |
| Key exchange             | X25519 (ECDH)          | Ephemeral keypairs per session |
| Key derivation           | HKDF-SHA256            | Derives symmetric keys from ECDH output |
| Authenticated encryption | AES-256-GCM            | Hardware accelerated on most modern MCUs |
| Device address           | SHA3-256(pubkey)[0..5] | First 6 bytes = 48-bit address |
| Transcript hashing       | SHA3-256               | Binds handshake messages |

**Rationale for AES-256-GCM over ChaCha20-Poly1305:** Most embedded targets (ARM Cortex-M33 and above) include hardware AES acceleration. ChaCha20 is preferred when hardware AES is unavailable; implementations MAY substitute ChaCha20-Poly1305 and MUST advertise this in their capability descriptor (see Part 3: Service Layer).

---

## 4. Device Identity

### 4.1 Keypair generation

On first boot, or after a deliberate identity reset, a device generates a fresh Ed25519 keypair using a cryptographically secure RNG. The private key is stored in protected storage and never leaves the device.

```
identity_privkey, identity_pubkey = Ed25519.generate()
device_id = SHA3-256(identity_pubkey)[0:6]   // 48 bits
```

### 4.2 Device ID format

The device ID is a 6-byte value derived from the identity public key. It is used as the source/destination address in all Aether frames.

```
+--------+--------+--------+--------+--------+--------+
| byte 0 | byte 1 | byte 2 | byte 3 | byte 4 | byte 5 |
+--------+--------+--------+--------+--------+--------+
        SHA3-256(identity_pubkey), first 6 bytes
```

The full 32-byte public key is transmitted during the handshake, allowing the peer to verify that the device ID is legitimately derived from it.

### 4.3 Address privacy

A device MAY advertise using a randomised ephemeral address during discovery to prevent tracking. The ephemeral address is rotated at a configurable interval (default: 15 minutes). When a connection is established, the full identity public key is revealed to the peer during the handshake (see Section 6).

Devices that do not require privacy (e.g. fixed infrastructure nodes) MAY advertise their stable device ID directly.

---

## 5. Trust Model

### 5.1 Trust levels

Aether defines three trust levels that a device assigns to a peer:

| Level   | Meaning                                              | How established |
|---------|------------------------------------------------------|-----------------|
| Unknown | Peer's public key has never been seen                | Default         |
| Known   | Peer's public key is stored; identity is verifiable  | Out-of-band key exchange |
| Trusted | Known + explicitly granted elevated permissions      | Application layer policy |

The protocol guarantees authenticated encryption for all levels. The distinction between Known and Trusted is available to the application layer but has no effect on the protocol framing.

### 5.2 Trust-on-first-use (TOFU)

An implementation MAY support TOFU: the first time a peer is seen, its public key is automatically stored and the trust level becomes Known. Subsequent connections verify against the stored key. This is similar to SSH host key behaviour.

TOFU MUST be a deliberate configuration choice. The default behaviour is to reject connections from peers whose public key is not already known, unless the application layer explicitly accepts them.

### 5.3 Key revocation

Aether does not define a revocation mechanism at the protocol level. Key revocation is the responsibility of the application or service layer. A device that generates a new identity keypair (e.g. after a factory reset) will have a new device ID and will appear as a completely new device to all peers.

---

## 6. Session Handshake

The Aether handshake is based on the Noise Protocol Framework pattern **XX** (mutual authentication, both sides transmit their static public keys). This pattern was chosen because:

- Both sides authenticate each other (unlike one-sided patterns)
- Neither side's identity is revealed to passive observers
- It is well-studied and has multiple independent implementations

### 6.1 Handshake overview

```
Initiator (I)                                   Responder (R)
─────────────────────────────────────────────────────────────

  Generate ephemeral keypair (e_I)
  ─── msg1: e_I.pubkey ──────────────────────────>
                                  Generate ephemeral keypair (e_R)
                                  Compute DH(e_R.priv, e_I.pub) → k1
  <─── msg2: e_R.pubkey, Enc(k1, identity_pubkey_R) ───
  
  Compute DH(e_I.priv, e_R.pub) → k1 (same)
  Decrypt identity_pubkey_R, verify device_id_R
  Compute DH(identity_priv_I, e_R.pub) → k2
  ─── msg3: Enc(k1+k2, identity_pubkey_I) ──────>
                                  Decrypt identity_pubkey_I, verify device_id_I
                                  Compute DH(e_R.priv, identity_pub_I) → k2

  Both sides derive session keys:
  session_key_send, session_key_recv = HKDF(k1 || k2, transcript_hash)
```

### 6.2 Handshake message formats

**msg1** (Initiator → Responder):
```
+--------+--------+------- ... -------+
| type=1 | flags  | e_I.pubkey (32B)  |
+--------+--------+------- ... -------+
```

**msg2** (Responder → Initiator):
```
+--------+--------+------- ... -------+------- ... --------+------------ ... -----------+
| type=2 | flags  | e_R.pubkey (32B)  | ciphertext (32+16B)| mac (16B)                  |
+--------+--------+------- ... -------+------- ... --------+------------ ... -----------+
ciphertext = AES-256-GCM(key=k1, plaintext=identity_pubkey_R, aad=transcript_hash_so_far)
```

**msg3** (Initiator → Responder):
```
+--------+--------+------- ... --------+------------ ... -----------+
| type=3 | flags  | ciphertext (32+16B)| mac (16B)                  |
+--------+--------+------- ... --------+------------ ... -----------+
ciphertext = AES-256-GCM(key=k1+k2, plaintext=identity_pubkey_I, aad=transcript_hash_so_far)
```

### 6.3 Session key derivation

After the handshake, both sides derive two symmetric keys (one per direction) using HKDF:

```
transcript_hash = SHA3-256(msg1 || msg2 || msg3)

key_material = HKDF-SHA256(
    ikm  = DH_k1 || DH_k2,
    salt = transcript_hash,
    info = "aether-v0.1-session"
)

session_key_I_to_R = key_material[0:32]
session_key_R_to_I = key_material[32:64]
```

### 6.4 Handshake failure modes

| Failure                              | Response                          |
|--------------------------------------|-----------------------------------|
| Unknown peer (TOFU disabled)         | Send REJECT frame, close link     |
| Identity mismatch (device_id ≠ hash) | Send REJECT frame, log anomaly    |
| MAC verification failure             | Silently drop, do not respond     |
| Timeout (no msg2 within 2s)          | Retry up to 3 times, then abort   |

Silently dropping on MAC failure (rather than sending an error) prevents oracle attacks.

---

## 7. Data Frame Encryption

After a successful handshake, all data frames are encrypted using AES-256-GCM with the session key for that direction.

### 7.1 Nonce construction

Nonces are 96-bit values constructed as:

```
nonce = session_id (32 bits) || message_counter (64 bits)
```

The message counter starts at 0 and increments by 1 for each frame. A device MUST NOT send more than 2^64 frames on a single session key (this limit is theoretical; sessions will be renegotiated long before this).

If a received message counter is not greater than the last accepted counter, the frame is silently dropped (replay protection).

### 7.2 Data frame format

```
+--------+-----------+----------------+--------- ... ---------+---------+
| flags  | session_id| msg_counter(8B)| ciphertext            | tag(16B)|
+--------+-----------+----------------+--------- ... ---------+---------+
  1 byte    2 bytes       8 bytes          variable              16 bytes
```

The `flags` byte encodes frame type, priority, and fragmentation bits (defined in Part 2: Link Layer).

The AAD (additional authenticated data) for GCM is: `flags || session_id || msg_counter`

This means the header is authenticated but not encrypted, allowing routers and relays to inspect routing metadata without decrypting the payload.

---

## 8. Identity Rotation

A device may choose to rotate its long-term identity (generate a new keypair). This results in a new device ID. There is intentionally no migration path at the protocol level — the new identity is treated as a completely new device by all peers.

Applications that need continuity across identity rotation (e.g. a smart lock that shouldn't lose access after a firmware reset) must handle this at the application layer, for example by embedding a secondary "device serial number" in the service descriptor.

---

## 9. Out-of-Scope (for this document)

The following are explicitly deferred to other parts of the specification:

- Discovery and advertisement format (Part 2: Link Layer)
- Service capability descriptors (Part 3: Service Layer)
- Mesh routing and multi-hop sessions (Part 4: Mesh)
- Group sessions and multicast encryption (Part 5: Group Sessions)
- Key distribution and PKI for large deployments (Part 6: Enterprise Extensions)

---

## Appendix A: Comparison with Bluetooth Security Modes

| Feature                      | Bluetooth LE (Security Mode 1, Level 4) | Aether             |
|------------------------------|-----------------------------------------|--------------------|
| Long-term identity           | BD_ADDR (hardware, not crypto-derived)  | Ed25519 pubkey     |
| Pairing required             | Yes                                     | No                 |
| Persistent bonding state     | Yes (both sides)                        | No                 |
| Forward secrecy              | Optional (LE Secure Connections only)   | Always             |
| Identity hiding during scan  | Optional (RPA)                          | Default            |
| Encryption algorithm         | AES-CCM-128                             | AES-256-GCM        |
| Handshake basis              | SMP (custom, complex)                   | Noise XX (audited) |
| Spec pages to understand it  | ~300                                    | This document      |

---

## Appendix B: Reference Implementations (planned)

- `libaether-core` — C99, no dependencies, runs on bare-metal MCUs
- `aether-sim` — C# simulator for host-side development and testing
- `aether-linux` — Linux host stack (userspace daemon + kernel driver)

---

*End of Part 1. Next: Part 2 — Link Layer & Frame Format*
# Aether Protocol Specification
## Part 2: Link Layer & Frame Format
**Version:** 0.1-draft  
**Status:** Working Draft  
**Depends on:** Part 1 (Identity & Security Model)

---

## 1. Overview

The link layer is responsible for:
- Framing raw radio bytes into typed, versioned packets
- Device advertisement and discovery
- Connection establishment and teardown
- Flow control and acknowledgement
- Fragmentation and reassembly of large payloads

The link layer sits directly above the PHY (radio hardware) and below the security layer. It is intentionally thin — it does not attempt to do routing, service negotiation, or application logic. Those belong in higher layers.

---

## 2. PHY Assumptions

Aether does not define a PHY. It assumes the following interface from the radio layer:

| Property | Requirement |
|---|---|
| Frequency band | 2.4 GHz ISM (same as BLE/Wi-Fi/Zigbee) |
| Modulation | GFSK or O-QPSK (implementation defined) |
| Raw MTU | Minimum 255 bytes per radio packet |
| Channel hopping | Supported (implementation defined schedule) |
| RSSI | Exposed to link layer for power management hints |
| TX power control | Exposed to link layer |

**Rationale:** By not defining the PHY, Aether can run on any compliant radio chip. Reference implementations target the Nordic nRF5340 using its IEEE 802.15.4 radio mode, which satisfies all the above requirements.

---

## 3. Frame Structure

Every Aether frame begins with a 4-byte common header, followed by a type-specific body.

### 3.1 Common header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  |  Type |     Flags     |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Bits | Description |
|---|---|---|
| Ver | 4 | Protocol version. Current = 0x1. Frames with unknown versions MUST be silently dropped. |
| Type | 4 | Frame type (see Section 3.2) |
| Flags | 8 | Type-specific flags (see per-type sections) |
| Length | 16 | Total frame length in bytes, including this header |

### 3.2 Frame types

| Value | Name | Direction | Description |
|---|---|---|---|
| 0x0 | ADV | Broadcast | Advertisement beacon |
| 0x1 | SCAN_REQ | Unicast | Request full capability descriptor |
| 0x2 | SCAN_RSP | Unicast | Full capability descriptor response |
| 0x3 | CONN_REQ | Unicast | Connection request (begins handshake) |
| 0x4 | CONN_RSP | Unicast | Connection response (handshake msg2) |
| 0x5 | CONN_FIN | Unicast | Handshake complete (handshake msg3) |
| 0x6 | DATA | Unicast | Encrypted application data |
| 0x7 | ACK | Unicast | Acknowledgement |
| 0x8 | NACK | Unicast | Negative acknowledgement / error |
| 0x9 | DISC | Unicast | Graceful disconnection |
| 0xA | PING | Unicast | Keepalive probe |
| 0xB | PONG | Unicast | Keepalive response |
| 0xC–0xE | — | — | Reserved |
| 0xF | VENDOR | Any | Vendor-defined extension |

---

## 4. Discovery

Discovery is how a device announces its presence and how peers find it. It is designed to be fast, privacy-preserving by default, and low-power.

### 4.1 ADV frame

A device in advertising mode periodically broadcasts ADV frames. The broadcast interval is configurable (default: 200ms for active advertising, 1000ms for background advertising).

```
+--------+-----------+-----------+----------+------- ... -------+
| Header | src_addr  | adv_flags | cap_hash | adv_payload       |
| (4B)   | (6B)      | (1B)      | (4B)     | (variable, ≤60B)  |
+--------+-----------+-----------+----------+------- ... -------+
```

**src_addr** — 6-byte device ID (or ephemeral address if privacy mode is active, see Part 1 §4.3).

**adv_flags:**

| Bit | Meaning |
|---|---|
| 0 | Connectable — device accepts connection requests |
| 1 | Privacy mode — src_addr is ephemeral |
| 2 | Low power — device has restricted duty cycle |
| 3 | Infrastructure — fixed node (e.g. sensor hub, gateway) |
| 4–7 | Reserved |

**cap_hash** — first 4 bytes of SHA3-256 over the device's full capability descriptor (defined in Part 3). Peers that already have the full descriptor cached can skip the SCAN_REQ/RSP exchange.

**adv_payload** — optional, up to 60 bytes. MAY contain a human-readable device name (UTF-8, not null-terminated) prefixed by a 1-byte length field. Additional fields may be defined in future versions.

### 4.2 SCAN_REQ / SCAN_RSP

When a scanner wants the full capability descriptor (either because it has no cached version or the cap_hash has changed), it sends a SCAN_REQ:

```
SCAN_REQ body:
+--------+-----------+-----------+
| Header | src_addr  | dst_addr  |
| (4B)   | (6B)      | (6B)      |
+--------+-----------+-----------+
```

The advertiser responds with a SCAN_RSP containing the full CBOR-encoded capability descriptor (see Part 3). SCAN_RSP frames MAY be fragmented using the fragmentation mechanism in Section 7.

### 4.3 Active vs passive scanning

A device in **active scan** mode sends SCAN_REQ frames. A device in **passive scan** mode only listens to ADV frames and does not send SCAN_REQ. Passive scanning is used when only presence detection is needed (e.g. proximity detection, indoor positioning).

---

## 5. Connection Establishment

Connections are always initiated by one device (the initiator) toward another (the responder). The connection setup is a three-message exchange that simultaneously establishes the link layer connection and performs the Part 1 Noise XX handshake.

### 5.1 CONN_REQ

```
+--------+-----------+-----------+------------+--- ... ---+
| Header | src_addr  | dst_addr  | session_id | hs_msg1   |
| (4B)   | (6B)      | (6B)      | (2B)       | (34B)     |
+--------+-----------+-----------+------------+--- ... ---+
```

**session_id** — a random 16-bit value chosen by the initiator. Used to identify this connection in subsequent frames. Scoped to the device pair; not globally unique.

**hs_msg1** — handshake message 1 from Part 1 §6.1 (ephemeral pubkey, 32 bytes + 2 bytes type/flags).

### 5.2 CONN_RSP

```
+--------+-----------+-----------+------------+--- ... ---+
| Header | src_addr  | dst_addr  | session_id | hs_msg2   |
| (4B)   | (6B)      | (6B)      | (2B)       | (80B)     |
+--------+-----------+-----------+------------+--- ... ---+
```

**hs_msg2** — handshake message 2 from Part 1 §6.1 (ephemeral pubkey + encrypted identity, 32 + 48 bytes).

If the responder does not recognise the initiator's identity (after decrypting hs_msg2's payload in the following CONN_FIN), it sends a NACK with error code 0x01 (identity unknown) and the connection is terminated.

### 5.3 CONN_FIN

```
+--------+-----------+-----------+------------+--- ... ---+
| Header | src_addr  | dst_addr  | session_id | hs_msg3   |
| (4B)   | (6B)      | (6B)      | (2B)       | (48B)     |
+--------+-----------+-----------+------------+--- ... ---+
```

After CONN_FIN is received and verified, both sides derive session keys (Part 1 §6.3) and the connection is established. All subsequent frames on this session use session_id to identify the connection.

### 5.4 Connection state machine

```
IDLE ──CONN_REQ──> HANDSHAKING ──CONN_FIN──> CONNECTED ──DISC──> IDLE
                        │                         │
                      NACK                    timeout/error
                        │                         │
                       IDLE <────────────────────────
```

A device may have multiple simultaneous connections, each identified by a (peer_addr, session_id) tuple.

---

## 6. Data Transfer

### 6.1 DATA frame

```
+--------+-----------+-----------+------------+----------+--- ... ---+---------+
| Header | src_addr  | dst_addr  | session_id | msg_seq  | ciphertext| tag     |
| (4B)   | (6B)      | (6B)      | (2B)       | (4B)     | (variable)| (16B)   |
+--------+-----------+-----------+------------+----------+--- ... ---+---------+
```

**msg_seq** — monotonically increasing 32-bit sequence number, per-direction, starting at 0. Used for ordering, deduplication, and replay detection. Wraps at 2^32 — sessions MUST be renegotiated before wrap (implementations should renegotiate at 2^31 as a safety margin).

**ciphertext + tag** — as defined in Part 1 §7. The AAD includes the entire unencrypted header portion of the DATA frame.

### 6.2 ACK frame

```
+--------+-----------+-----------+------------+----------+
| Header | src_addr  | dst_addr  | session_id | ack_seq  |
| (4B)   | (6B)      | (6B)      | (2B)       | (4B)     |
+--------+-----------+-----------+------------+----------+
```

**ack_seq** — the msg_seq of the highest in-order DATA frame received. Cumulative acknowledgement (all frames up to and including ack_seq are confirmed received).

ACK is sent after every DATA frame by default. An implementation MAY delay ACK by up to 10ms to batch acknowledgements (delayed ACK mode), negotiated during connection setup via the capability descriptor.

### 6.3 NACK frame

```
+--------+-----------+-----------+------------+----------+----------+
| Header | src_addr  | dst_addr  | session_id | err_code | err_seq  |
| (4B)   | (6B)      | (6B)      | (2B)       | (1B)     | (4B)     |
+--------+-----------+-----------+------------+----------+----------+
```

| err_code | Meaning |
|---|---|
| 0x00 | Generic error |
| 0x01 | Identity unknown |
| 0x02 | MAC verification failed |
| 0x03 | Replay detected |
| 0x04 | Session not found |
| 0x05 | Buffer full — slow down |
| 0x06 | Fragmentation error |
| 0x07–0xFE | Reserved |
| 0xFF | Vendor-defined |

### 6.4 Retransmission

If no ACK is received within the retransmit timeout (default: 50ms), the sender retransmits the DATA frame with the same msg_seq. After 5 consecutive retransmit failures, the connection is considered lost and both sides return to IDLE.

Retransmit timeout uses exponential backoff: 50ms, 100ms, 200ms, 400ms, 800ms.

---

## 7. Fragmentation

The PHY MTU is at minimum 255 bytes. The Aether frame header and addressing consume 28 bytes, leaving 227 bytes for payload per physical packet. Service layer messages (e.g. capability descriptors, large RPC payloads) may exceed this.

### 7.1 Fragmentation flags

The Header `Flags` byte for DATA and SCAN_RSP frames uses bits 0–1 for fragmentation:

| Bits 1:0 | Meaning |
|---|---|
| 00 | Unfragmented (complete message in this frame) |
| 01 | First fragment |
| 10 | Middle fragment |
| 11 | Last fragment |

### 7.2 Fragment frame

Fragmented frames add a 3-byte fragmentation header immediately after the common header:

```
+--------+--------+----------+
| frag_id| total  | frag_seq |
| (1B)   | (1B)   | (1B)     |
+--------+--------+----------+
```

**frag_id** — identifies this fragmented message (scoped to the session). Allows interleaving of multiple fragmented messages.

**total** — total number of fragments in this message (max 255, limiting reassembled payload to ~57KB).

**frag_seq** — 0-indexed position of this fragment.

Reassembly timeout: if all fragments are not received within 2 seconds, the partial message is discarded and a NACK with err_code 0x06 is sent.

---

## 8. Connection Teardown

### 8.1 Graceful disconnect

Either side may send a DISC frame to gracefully terminate a connection:

```
+--------+-----------+-----------+------------+----------+
| Header | src_addr  | dst_addr  | session_id | reason   |
| (4B)   | (6B)      | (6B)      | (2B)       | (1B)     |
+--------+-----------+-----------+------------+----------+
```

| reason | Meaning |
|---|---|
| 0x00 | Normal termination |
| 0x01 | Going to sleep / power saving |
| 0x02 | Protocol error |
| 0x03 | Session key expiry |
| 0x04–0xFE | Reserved |
| 0xFF | Vendor-defined |

The receiver of a DISC frame MUST NOT send any further DATA frames on that session_id. Session state may be cleaned up immediately.

### 8.2 Implicit disconnect

A connection is considered implicitly disconnected if no frame (including PING) is received from the peer for the idle timeout period (default: 30 seconds). Implementations SHOULD send PING frames at half the idle timeout interval to keep the connection alive when no data is being transferred.

---

## 9. Power Management

Low-power operation is a first-class concern. The following mechanisms are available:

**Advertising interval back-off:** A device with no active connections should increase its advertising interval from 200ms to 1000ms after 60 seconds of no connection attempts.

**Duty cycle negotiation:** During connection setup (via capability descriptor), both sides may agree on a duty cycle schedule — periods when the radio is guaranteed to be on vs. off. This replaces Bluetooth's connection interval/latency parameters with an explicit, human-readable schedule.

**Low-power flag in ADV:** A device that is in restricted power mode sets bit 2 of adv_flags. Peers should not expect fast responses from such devices and should prefer batching data.

**Radio sleep between slots:** When a duty cycle schedule is active, the link layer informs the PHY of the next expected wake time so the radio can be fully powered down between slots.

---

## 10. Timing Requirements

| Parameter | Default | Configurable |
|---|---|---|
| ADV interval (active) | 200ms | Yes, 20ms–10s |
| ADV interval (background) | 1000ms | Yes |
| Scan window | 100ms | Yes |
| CONN_RSP timeout | 500ms | No |
| ACK timeout | 50ms | Yes, 10ms–500ms |
| Retransmit max attempts | 5 | Yes |
| Idle timeout | 30s | Yes, 5s–300s |
| Fragmentation reassembly timeout | 2s | No |

---

## Appendix: Frame Size Summary

| Frame type | Fixed size | Max total size |
|---|---|---|
| ADV | 17B header+addr | 77B (60B payload) |
| SCAN_REQ | 16B | 16B |
| SCAN_RSP | 16B + descriptor | 16B + ~2KB (fragmented) |
| CONN_REQ | 18B + 34B hs | 52B |
| CONN_RSP | 18B + 80B hs | 98B |
| CONN_FIN | 18B + 48B hs | 66B |
| DATA | 28B + payload + 16B tag | PHY MTU (fragmented for larger) |
| ACK | 24B | 24B |
| NACK | 25B | 25B |
| DISC | 25B | 25B |

---

*End of Part 2. Next: Part 3 — Service Layer*
# Aether Protocol Specification
## Part 3: Service Layer
**Version:** 0.1-draft  
**Status:** Working Draft  
**Depends on:** Part 1 (Identity & Security Model), Part 2 (Link Layer)

---

## 1. Overview

The service layer answers the question: "what can this device do, and how do I talk to it?"

In Bluetooth, the answer is spread across hundreds of pages of profile specifications, each with its own framing, vocabulary, and quirks. A2DP works nothing like HFP, which works nothing like HID, which works nothing like GATT. The result is that adding a new capability to a device means learning and implementing a new profile from scratch.

Aether replaces all of this with three ideas:

1. **Capability descriptors** — a machine-readable document, encoded in CBOR, that describes everything a device can do. Sent once during discovery.
2. **Service descriptors** — a typed description of a single capability: its unique ID, version, callable methods, and async events.
3. **One RPC mechanism** — all service communication uses the same framing. There is no per-service wire format.

---

## 2. Encoding

All service layer data is encoded in **CBOR** (Concise Binary Object Representation, RFC 8949). CBOR is chosen over JSON for compactness (critical on embedded devices), over Protocol Buffers for self-describing schema (no .proto file needed to parse), and over MessagePack for standardisation (RFC status, wide library support).

Implementations MUST support CBOR major types 0–5 (unsigned int, negative int, byte string, text string, array, map). Support for major types 6 (tagged) and 7 (float/simple) is OPTIONAL and MUST be handled gracefully — unknown tagged values are ignored, not an error.

Maximum capability descriptor size: 2048 bytes (before CBOR encoding). Implementations SHOULD keep descriptors well under this limit. If a descriptor exceeds 2048 bytes it MUST be rejected with NACK err_code 0x00.

---

## 3. Capability Descriptor

The capability descriptor is the top-level document a device makes available during discovery (delivered via SCAN_RSP, see Part 2 §4.2). It is a CBOR map with the following keys:

### 3.1 Top-level keys

| Key | CBOR type | Required | Description |
|---|---|---|---|
| `"v"` | uint | Yes | Descriptor version. Current = 1 |
| `"di"` | map | Yes | Device info (see §3.2) |
| `"sv"` | array | Yes | Array of service descriptors (see §4). May be empty. |
| `"cc"` | map | No | Crypto capabilities (see §3.3) |
| `"ext"` | map | No | Vendor-defined extensions. Keys MUST be text strings prefixed with a reverse-DNS vendor identifier (e.g. `"com.example.feature"`). Unknown keys MUST be ignored. |

### 3.2 Device info (`"di"`)

| Key | CBOR type | Required | Description |
|---|---|---|---|
| `"n"` | text | Yes | Human-readable device name. Max 64 bytes UTF-8. |
| `"sv"` | text | Yes | Software/firmware version (semver, e.g. `"1.2.3"`). |
| `"hv"` | text | No | Hardware version string. |
| `"sn"` | bytes | No | Device serial number. Max 32 bytes. Opaque to the protocol. |
| `"mn"` | text | No | Manufacturer name. Max 64 bytes. |

### 3.3 Crypto capabilities (`"cc"`)

| Key | CBOR type | Default | Description |
|---|---|---|---|
| `"cc20"` | bool | false | Supports ChaCha20-Poly1305 as alternative to AES-256-GCM |
| `"mtu"` | uint | 227 | Maximum DATA frame payload in bytes |
| `"dack"` | bool | false | Supports delayed ACK mode |

If the `"cc"` key is absent, all values take their defaults.

### 3.4 Example capability descriptor (JSON-equivalent for readability)

```json
{
  "v": 1,
  "di": {
    "n": "Aether Sensor Node v1",
    "sv": "0.1.0",
    "mn": "Acme Sensors Ltd",
    "sn": "<16 bytes binary>"
  },
  "cc": {
    "cc20": true,
    "mtu": 227
  },
  "sv": [
    {
      "id": "<16 bytes — standard temperature service UUID>",
      "v": "1.0.0",
      "m": [ ... ],
      "e": [ ... ]
    }
  ]
}
```

---

## 4. Service Descriptor

Each entry in the `"sv"` array is a service descriptor — a description of one capability the device offers.

### 4.1 Service descriptor keys

| Key | CBOR type | Required | Description |
|---|---|---|---|
| `"id"` | bytes (16) | Yes | Service UUID. See §4.2 for assignment. |
| `"v"` | text | Yes | Service implementation version (semver). |
| `"m"` | array | No | Array of method descriptors (see §4.3). |
| `"e"` | array | No | Array of event descriptors (see §4.4). |
| `"ro"` | bool | No | Read-only — device only emits events, accepts no calls. Default: false. |

### 4.2 Service UUID assignment

Service UUIDs are 16-byte (128-bit) values. Two namespaces:

**Standard namespace:** Top bit (bit 127) is 0. UUIDs in this range are assigned by the Aether Service Registry (community-governed, open process, GitHub-based). Any device implementing a standard service MUST conform to the published interface for that UUID.

**Vendor namespace:** Top bit (bit 127) is 1. Remaining 127 bits are chosen by the vendor. Vendors SHOULD use a UUID derived from their reverse-DNS domain to avoid collisions. Vendor services are not required to be public.

Well-known standard service UUIDs (v0.1 registry):

| Service | UUID (first 4 bytes shown) | Description |
|---|---|---|
| Temperature | `0x00000001 ...` | Read temperature in millidegrees Celsius |
| Humidity | `0x00000002 ...` | Read relative humidity (0–100000, millipercent) |
| Battery | `0x00000003 ...` | Read battery level and charging state |
| Generic I/O | `0x00000004 ...` | Digital pin read/write |
| Serial stream | `0x00000005 ...` | Bidirectional byte stream (replaces SPP) |
| Audio source | `0x00000006 ...` | Encoded audio output (replaces A2DP source) |
| Audio sink | `0x00000007 ...` | Encoded audio input (replaces A2DP sink) |
| HID keyboard | `0x00000008 ...` | Keyboard input events |
| HID pointer | `0x00000009 ...` | Mouse/pointer input events |
| Location | `0x0000000A ...` | GPS or indoor positioning data |

Full UUIDs and interface definitions are published at `https://github.com/aether-protocol/service-registry` (planned).

### 4.3 Method descriptor

A method is a callable RPC endpoint. The caller sends a request; the callee sends a response.

| Key | CBOR type | Required | Description |
|---|---|---|---|
| `"mid"` | uint (1B) | Yes | Method ID, unique within this service. 0x00–0xEF standard, 0xF0–0xFF vendor. |
| `"n"` | text | Yes | Method name. For documentation and debugging. Max 32 bytes. |
| `"req"` | map | No | CBOR schema of request arguments. See §5. |
| `"rsp"` | map | No | CBOR schema of response. See §5. |
| `"to"` | uint | No | Suggested timeout in milliseconds. Default: 1000. |

### 4.4 Event descriptor

An event is an async notification sent from device to peer without a prior request. Events are one-way.

| Key | CBOR type | Required | Description |
|---|---|---|---|
| `"eid"` | uint (1B) | Yes | Event ID, unique within this service. |
| `"n"` | text | Yes | Event name. Max 32 bytes. |
| `"pl"` | map | No | CBOR schema of event payload. See §5. |
| `"rate"` | uint | No | Maximum emission rate in events/second. 0 = no limit. |

---

## 5. Schema System

Methods and events declare their argument/payload schema using a simple inline type system. This is intentionally minimal — it provides enough information for code generation and basic validation, without becoming a full IDL.

### 5.1 Type descriptors

A schema is a CBOR map from field name (text) to type descriptor. A type descriptor is a CBOR map:

| Key | CBOR type | Description |
|---|---|---|
| `"t"` | text | Type name. See §5.2. |
| `"opt"` | bool | Optional field. Default: false (required). |
| `"desc"` | text | Human-readable description. |
| `"min"` | number | Minimum value (numeric types only). |
| `"max"` | number | Maximum value (numeric types only). |
| `"len"` | uint | Maximum length (bytes/text/array types only). |

### 5.2 Primitive types

| Type name | CBOR encoding | Description |
|---|---|---|
| `"u8"` | uint | Unsigned 8-bit integer |
| `"u16"` | uint | Unsigned 16-bit integer |
| `"u32"` | uint | Unsigned 32-bit integer |
| `"u64"` | uint | Unsigned 64-bit integer |
| `"i32"` | int | Signed 32-bit integer |
| `"i64"` | int | Signed 64-bit integer |
| `"f32"` | float | 32-bit IEEE 754 float |
| `"bool"` | bool | Boolean |
| `"text"` | text | UTF-8 string |
| `"bytes"` | bytes | Raw byte array |
| `"ts"` | uint | Unix timestamp in milliseconds (u64) |
| `"void"` | (absent) | No value — used for methods with no response |

Arrays are expressed by appending `[]` to a type name: `"u8[]"` is a byte array with schema-level element constraints (distinct from CBOR bytes type).

---

## 6. RPC Framing

All service calls use the same wire format, carried as the payload of a DATA frame (Part 2 §6.1).

### 6.1 Request frame payload

```
+---------- ... ----------+-------+-------+--------+--- ... ---+
| service_id (16B)        | m_id  | call_id| flags  | CBOR args |
+---------- ... ----------+-------+-------+--------+--- ... ---+
```

**service_id** — 16-byte UUID of the target service.

**m_id** — 1-byte method ID within that service.

**call_id** — 2-byte caller-assigned identifier for this call. Used to match responses to requests. A device may have multiple outstanding calls to different services.

**flags:**
| Bit | Meaning |
|---|---|
| 0 | Response expected (0 = fire-and-forget, 1 = awaiting response) |
| 1 | This is a response (distinguishes request from response in the same framing) |
| 2 | This is an event (no call_id matching needed) |
| 3–7 | Reserved |

**CBOR args** — the method arguments encoded as a CBOR map matching the method's `"req"` schema. If the method has no arguments, this field is omitted.

### 6.2 Response frame payload

Same format as request, with bit 1 of flags set. The call_id matches the call_id from the request. The CBOR payload matches the method's `"rsp"` schema.

### 6.3 Event frame payload

Same format, with bit 2 of flags set. call_id is 0x0000 (ignored). service_id + m_id is replaced by service_id + e_id (event ID).

### 6.4 Error response

If a method call fails, the responder sends a response with a special error service_id (`0xFFFFFFFF...FF`, 16 bytes of 0xFF), carrying a CBOR map:

```json
{
  "call_id": 42,
  "err": 3,
  "msg": "temperature sensor not ready"
}
```

Standard error codes:

| Code | Meaning |
|---|---|
| 1 | Unknown service |
| 2 | Unknown method |
| 3 | Device busy / not ready |
| 4 | Invalid arguments |
| 5 | Permission denied |
| 6 | Timeout |
| 7–127 | Reserved |
| 128–255 | Vendor-defined |

---

## 7. Example: Temperature Service

To make the above concrete, here is the full definition of the standard Temperature service.

**Service UUID:** `00000000-0000-0000-0000-000000000001` (128-bit)

**Methods:**

| ID | Name | Request | Response |
|---|---|---|---|
| 0x01 | `read` | (none) | `{"t": i32, "unit": u8}` |
| 0x02 | `set_interval` | `{"ms": u32}` | (void) |

**Events:**

| ID | Name | Payload |
|---|---|---|
| 0x01 | `reading` | `{"t": i32, "unit": u8, "ts": ts}` |

**Notes:**
- Temperature `t` is in millidegrees. 21500 = 21.5°C.
- `unit`: 0 = Celsius, 1 = Fahrenheit, 2 = Kelvin.
- `set_interval` sets how often `reading` events are emitted. 0 = disable events.

**Wire example — calling `read` (hex):**
```
service_id: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 01
m_id:       01
call_id:    00 2A
flags:      01   (response expected)
args:       (empty)
```

**Wire example — response:**
```
service_id: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 01
m_id:       01
call_id:    00 2A
flags:      02   (is response)
payload:    A2          -- CBOR map, 2 entries
            61 74       -- key "t"
            19 5402     -- uint 21506 (21.506°C)
            64 75 6E 69 74 -- key "unit"
            00          -- uint 0 (Celsius)
```

---

## 8. Service Registration Process

The Aether Service Registry is an open, GitHub-based process:

1. Author opens a pull request proposing a new service UUID + interface definition (markdown + JSON schema)
2. A 2-week comment period allows community feedback
3. Two maintainer approvals required to merge
4. Merged services are assigned a permanent UUID and versioned

Versioning policy: breaking changes to a service interface require a new UUID. Non-breaking additions (new optional methods/events) increment the minor version. The registry is the source of truth for all standard UUIDs.

---

## Appendix: CBOR Encoding Size Estimates

| Descriptor | Estimated CBOR size |
|---|---|
| Minimal (device_info only, no services) | ~80 bytes |
| Single simple service (2 methods, 1 event) | ~250 bytes |
| 5 services with full schemas | ~900 bytes |
| Complex device (10 services) | ~1800 bytes |
| Hard limit | 2048 bytes |

For devices with descriptors approaching the limit, OPTIONAL fields (`"desc"`, `"mn"`, `"hv"`) should be omitted first.

---

*End of Part 3. Future parts: Part 4 (Mesh Routing), Part 5 (Group Sessions), Part 6 (Enterprise Extensions)*
