# Aether Simulator

A software-only implementation of the Aether protocol. Two virtual nodes communicate over an in-process transport, exercising the full stack: handshake, encryption, service layer RPC.

## Requirements

- .NET 8 or later

## Running

```bash
dotnet run
```

## Structure

```
sim/
  src/
    AetherNode.cs         Virtual protocol node
    LinkLayer.cs          Simulated link layer (in-process transport)
    Crypto.cs             Ed25519, X25519, AES-256-GCM wrappers
    Handshake.cs          Noise XX state machine
    ServiceLayer.cs       Capability descriptor + RPC framing
    CapabilityDescriptor.cs  CBOR serialisation
  tests/
    HandshakeTests.cs     Conformance tests for Part 1
    LinkLayerTests.cs     Conformance tests for Part 2
    ServiceLayerTests.cs  Conformance tests for Part 3
```

## Status

Not yet implemented. This directory contains the planned structure.
