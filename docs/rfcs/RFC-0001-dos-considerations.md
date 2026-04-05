# RFC 0001: Denial-of-service considerations for the link layer

**Status:** Draft  
**Author:** Levente Simon  
**Created:** 2025-01-01  
**Affects:** Part 2 (new Section 11)

---

## Summary

The current Part 2 draft does not address what happens when a device is flooded with connection requests from unknown or malicious peers. This RFC adds a Section 11 defining three mandatory and two optional mitigations.

---

## Motivation

A device broadcasting an ADV frame with the Connectable bit set is publicly announcing that it will process CONN_REQ frames. An attacker can send an arbitrarily large number of CONN_REQ frames from randomised source addresses. Without mitigations, this can:

- Exhaust the device's handshake processing budget (CPU on constrained MCUs)
- Fill connection state tables
- Prevent legitimate connection attempts from succeeding
- Drain battery by keeping the radio and CPU active

Bluetooth has no protocol-level answer to this. We should do better.

---

## Detailed design

Add Section 11 to Part 2 as follows:

### 11. Denial-of-Service Considerations

#### 11.1 Connectable window

Devices SHOULD NOT set the Connectable flag in ADV frames permanently. Instead they SHOULD only set it during intentional pairing windows — for example, after a user presses a physical button, for a configurable duration (recommended default: 30 seconds). After the window expires, the Connectable flag is cleared and new CONN_REQ frames are silently dropped.

This is the most effective single mitigation. An attacker cannot flood connection requests to a device that is not accepting them.

Devices that legitimately need to be always-connectable (infrastructure nodes, gateways) MUST implement the rate limiting in §11.2.

#### 11.2 Connection request rate limiting (REQUIRED for always-connectable devices)

A device MUST implement rate limiting on incoming CONN_REQ frames. The following limits are REQUIRED minimums:

- No more than 10 CONN_REQ frames processed per second from distinct source addresses
- No more than 3 simultaneous in-progress handshakes at any time
- If either limit is exceeded, incoming CONN_REQ frames are silently dropped (not NACKed — a NACK response would itself become a resource cost)

Implementations MAY use stricter limits.

#### 11.3 Handshake asymmetry

The Noise XX handshake is deliberately structured so that the responder performs minimal work until msg3 (CONN_FIN) arrives and can be verified. Specifically:

- On receipt of CONN_REQ (msg1): the responder only stores the initiator's ephemeral public key (32 bytes) and generates its own ephemeral keypair. Cost: ~1μs on Cortex-M33.
- On receipt of CONN_FIN (msg3): the responder performs the full X25519 ECDH and verifies the initiator's identity. Cost: ~1ms on Cortex-M33.

An attacker sending only CONN_REQ frames without completing the handshake costs the responder very little. The expensive verification only happens when the initiator commits to completing the exchange.

Implementations MUST expire incomplete handshakes after the CONN_RSP timeout (500ms, see §10) and free all associated state.

#### 11.4 Source address validation (OPTIONAL)

An implementation MAY maintain a short-term blocklist of source addresses that have sent malformed frames or failed MAC verification. Entries expire after 60 seconds. This provides marginal benefit against attackers who reuse addresses but has no effect against attackers using randomised addresses. It is listed here for completeness, not as a recommended primary defence.

#### 11.5 Application-layer authentication gate (OPTIONAL)

Before the Aether protocol layer accepts a connection, the application MAY require the initiator's identity public key to be pre-approved (i.e. exist in a local allowlist). This is the strictest possible policy and appropriate for devices with a fixed set of known peers (e.g. a sensor that only talks to one gateway). It is not appropriate for devices intended to pair with arbitrary new devices.

---

## Worked example

A smart lock implementation:

1. Lock is not connectable by default (Connectable bit = 0 in ADV)
2. User presses physical button on lock
3. Lock sets Connectable = 1 for 30 seconds
4. Owner's phone sends CONN_REQ, handshake completes, session established
5. After 30 seconds (or immediately after successful connection), Connectable = 0

An attacker flooding CONN_REQ frames outside the 30-second window receives no response.

---

## Alternatives considered

**Proof-of-work on CONN_REQ:** Requiring the initiator to include a hashcash-style proof of work would make flooding expensive for the attacker. Rejected because it also makes legitimate connections slower and more power-hungry for mobile devices. The connectable window approach achieves similar DoS resistance with no cost to legitimate users.

**Challenge-response before handshake:** Adding a pre-handshake challenge round trip. Rejected because it adds latency to every connection and the Noise XX handshake already provides the right asymmetry.

---

## Backwards compatibility

This is a new section, not a change to existing sections. Implementations that do not implement §11.2 rate limiting are non-conformant for always-connectable mode but still interoperable — the mitigation is local to the device being protected.

---

## Security considerations

§11.3 documents a property of the existing handshake design that was not previously explicit. No change to the handshake itself is proposed.

---

## Open questions

- Should the default connectable window duration (30 seconds) be in the spec or left to implementations? Argument for: consistency across devices. Argument against: different device classes have very different needs.
- Should §11.2 rate limits be normative numbers in the spec or expressed as a principle with example values? Normative numbers are easier to test but may be wrong for some hardware classes.
