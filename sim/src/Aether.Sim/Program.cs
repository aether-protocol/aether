using System.Buffers.Binary;
using Aether.Core;
using PeterO.Cbor;

// ── Temperature service constants (Spec Part 3 §7) ───────────────────────────

// Service UUID: 00000000-0000-0000-0000-000000000001
static ReadOnlySpan<byte> TempServiceId() =>
    [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1];

const byte   MethodRead     = 0x01;
const byte   FlagRespExpect = 0x01;  // bit 0: response expected
const ushort CallId         = 0x002A;

// ── Helpers ───────────────────────────────────────────────────────────────────

static string Hex(ReadOnlySpan<byte> data, int wrap = 16)
{
    var sb = new System.Text.StringBuilder();
    for (int i = 0; i < data.Length; i++)
    {
        if (i > 0 && i % wrap == 0) sb.Append("\n              ");
        else if (i > 0) sb.Append(' ');
        sb.Append(data[i].ToString("X2"));
    }
    return sb.ToString();
}

static void Print(string tag, ReadOnlySpan<byte> frame)
{
    Console.WriteLine($"  {tag} ({frame.Length} bytes)");
    Console.WriteLine($"              {Hex(frame)}");
}

// Spec §7.1: nonce = fixed_iv XOR encode64(counter)
// encode64(counter) = 8-byte LE counter zero-padded to 12 bytes.
static byte[] BuildNonce(byte[] fixedIv, ulong counter)
{
    Span<byte> encoded = stackalloc byte[12];   // zero-initialised
    BinaryPrimitives.WriteUInt64LittleEndian(encoded, counter);
    byte[] nonce = new byte[12];
    for (int i = 0; i < 12; i++)
        nonce[i] = (byte)(fixedIv[i] ^ encoded[i]);
    return nonce;
}

// Simplified data frame: counter(8 B LE) ‖ ciphertext+tag
// AAD = counter bytes (binds the counter to the authentication tag).
static byte[] EncryptDataFrame(byte[] sessionKey, byte[] nonceIv, ulong counter, byte[] plaintext)
{
    byte[] hdr   = new byte[8];
    BinaryPrimitives.WriteUInt64LittleEndian(hdr, counter);
    byte[] nonce = BuildNonce(nonceIv, counter);
    byte[] ct    = Crypto.AesGcmEncrypt(sessionKey, nonce, plaintext, hdr);
    return [.. hdr, .. ct];
}

static byte[] DecryptDataFrame(byte[] sessionKey, byte[] nonceIv, ulong counter, byte[] frame)
{
    byte[] hdr   = frame[..8];
    byte[] ct    = frame[8..];
    byte[] nonce = BuildNonce(nonceIv, counter);
    return Crypto.AesGcmDecrypt(sessionKey, nonce, ct, hdr);
}

// Build the RPC request for Temperature.read (method takes no arguments).
// Layout: service_id(16) ‖ m_id(1) ‖ call_id(2 BE) ‖ flags(1)
static byte[] BuildRpcRequest()
{
    byte[] frame = new byte[20];
    TempServiceId().CopyTo(frame);
    frame[16] = MethodRead;
    BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(17), CallId);
    frame[19] = FlagRespExpect;
    return frame;
}

// New parser for responses coming from ServiceLayer
static (int MilliDegrees, byte Unit) ParseServiceLayerResponse(byte[] payload)
{
    if (payload.Length < 20)
        throw new InvalidDataException("Response too short");

    // Skip the 20-byte RPC header
    ReadOnlySpan<byte> cborData = payload.AsSpan(20);

    var cbor = CBORObject.DecodeFromBytes(cborData.ToArray());

    int t = cbor["t"].AsInt32();
    byte unit = (byte)cbor["unit"].AsInt32();

    return (t, unit);
}

{
// ─────────────────────────────────────────────────────────────────────────────
// Demo
// ─────────────────────────────────────────────────────────────────────────────

    Console.WriteLine("═══════════════════════════════════════════════════════");
    Console.WriteLine("  AETHER PROTOCOL SIMULATOR — End-to-End Demo");
    Console.WriteLine("═══════════════════════════════════════════════════════");
    Console.WriteLine();

// ── 1. Identity & Capabilities ───────────────────────────────────────────────

    var nodeA = new AetherNode("Node-A");
    var nodeB = new AetherNode("Node-B");

    Console.WriteLine("── Identity & Capabilities ─────────────────────────────");
    foreach (var (node, label) in new[] { (nodeA, "A"), (nodeB, "B") })
    {
        Console.WriteLine($"  Node-{label}");
        Console.WriteLine($"    device_id   = {Hex(node.DeviceId)}");
        Console.WriteLine($"    id_pub      = {Hex(node.IdentityPublicKey)}");
        Console.WriteLine($"    static_pub  = {Hex(node.StaticPublicKey)}");
        Console.WriteLine($"    binding_sig = {Hex(node.BindingSig, wrap: 32)}");

        // Show capability descriptor
        Console.WriteLine($"    descriptor  = {node.CapabilityDescriptor.DeviceInfo.Name} " +
                          $"(v{node.CapabilityDescriptor.Version}, " +
                          $"{node.CapabilityDescriptor.Services.Count} services)");
        Console.WriteLine();
    }

// Optional: Print the actual CBOR bytes of the descriptor (for debugging)
    Console.WriteLine("  Capability Descriptor CBOR (first 64 bytes):");
    var descBytes = nodeA.CapabilityDescriptor.ToCborBytes();
    Console.WriteLine($"    {Hex(descBytes.AsSpan(0, Math.Min(64, descBytes.Length)))}");
    Console.WriteLine();

// ── 2. Link layer ─────────────────────────────────────────────────────────────

    var link = new LinkLayer();
    var epA = link.EndpointA;
    var epB = link.EndpointB;

// ── 3. Noise XX handshake ─────────────────────────────────────────────────────

    Console.WriteLine("── Noise XX Handshake ──────────────────────────────────");

    var hsA = new HandshakeInitiator(
        nodeA.StaticPrivateKey, nodeA.StaticPublicKey,
        nodeA.IdentityPublicKey, nodeA.BindingSig);

    var hsB = new HandshakeResponder(
        nodeB.StaticPrivateKey, nodeB.StaticPublicKey,
        nodeB.IdentityPublicKey, nodeB.BindingSig);

// msg1: A → B
    byte[] msg1 = hsA.Step();
    await epA.SendAsync(msg1);
    byte[] msg1recv = await epB.ReceiveAsync();
    Print("msg1  A→B", msg1recv);
    Console.WriteLine();

// msg2: B → A
// B processes msg1, builds msg2 (encrypts its own static_pub+identity_pub+binding_sig)
    byte[] msg2 = hsB.Step(msg1recv);
    await epB.SendAsync(msg2);
    byte[] msg2recv = await epA.ReceiveAsync();
    Print("msg2  B→A", msg2recv);

// A processes msg2 — decrypts and verifies B's binding signature + device ID
    byte[] msg3 = hsA.Step(msg2recv);
    Console.WriteLine($"    binding_sig [OK] — A verified B's Ed25519 binding");
    Console.WriteLine($"    peer device_id  = {Hex(hsA.PeerDeviceId!)}");
    Console.WriteLine();

// msg3: A → B
// A encrypts its own static_pub+identity_pub+binding_sig
    await epA.SendAsync(msg3);
    byte[] msg3recv = await epB.ReceiveAsync();
    Print("msg3  A→B", msg3recv);

// B processes msg3 — decrypts and verifies A's binding signature + device ID
    hsB.Step(msg3recv);
    Console.WriteLine($"    binding_sig [OK] — B verified A's Ed25519 binding");
    Console.WriteLine($"    peer device_id  = {Hex(hsB.PeerDeviceId!)}");
    Console.WriteLine();

// ── Verify symmetric session state ────────────────────────────────────────────

    byte[] keyAtoB = hsA.SessionKeyToSend!;
    byte[] keyBtoA = hsA.SessionKeyToReceive!;
    byte[] nonceIvA = hsA.SessionNonceIV!;

    Console.WriteLine($"  session key I→R : {Hex(keyAtoB)}");
    Console.WriteLine($"  session key R→I : {Hex(keyBtoA)}");
    Console.WriteLine($"  nonce IV        : {Hex(nonceIvA)}");
    Console.WriteLine();

    bool keysMatch = keyAtoB.SequenceEqual(hsB.SessionKeyToReceive!)
                     && keyBtoA.SequenceEqual(hsB.SessionKeyToSend!)
                     && nonceIvA.SequenceEqual(hsB.SessionNonceIV!);

    Console.WriteLine(keysMatch
        ? "  [OK] Both sides derived identical session keys and nonce IV."
        : "  [FAIL] Session state mismatch — handshake is broken!");
    Console.WriteLine();

    if (!keysMatch) return;

// ── 4. Service Layer & RPC ───────────────────────────────────────────────────

    Console.WriteLine("── Service Layer & RPC ─────────────────────────────────");

    var serviceLayerB = new ServiceLayer(nodeB.CapabilityDescriptor);

    // Register Temperature.read handler on Node B
    serviceLayerB.RegisterHandler(
        new byte[16] { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 }, // Temperature service UUID
        0x01, // read method ID
        _ => CBORObject.NewMap()
            .Add("t", 21500)      // millidegrees Celsius
            .Add("unit", 0));     // 0 = Celsius

    Console.WriteLine("  Temperature.read handler registered on Node-B");

    // Build and send RPC request (same header as before)
    byte[] rpcRequest = BuildRpcRequest();   // your existing helper

    ulong counter = 0;
    byte[] encryptedRequest = EncryptDataFrame(keyAtoB, nonceIvA, counter, rpcRequest);

    await epA.SendAsync(encryptedRequest);
    Console.WriteLine("  [Request sent] Temperature.read()");

    // B receives, decrypts and processes through ServiceLayer
    byte[] receivedEncrypted = await epB.ReceiveAsync();
    byte[] decryptedRequest = DecryptDataFrame(hsB.SessionKeyToReceive!, nonceIvA, counter, receivedEncrypted);

    byte[]? responseBytes = serviceLayerB.ProcessRpcFrame(decryptedRequest);

    if (responseBytes != null)
    {
        ulong respCounter = 0;
        byte[] encryptedResponse = EncryptDataFrame(keyBtoA, nonceIvA, respCounter, responseBytes);
        await epB.SendAsync(encryptedResponse);

        // A receives and decrypts
        byte[] rspEncrypted = await epA.ReceiveAsync();
        byte[] rspDecrypted = DecryptDataFrame(hsA.SessionKeyToReceive!, nonceIvA, respCounter, rspEncrypted);

        Console.WriteLine("  [Response received and decrypted]");

        // New parser for ServiceLayer response (CBOR payload after 20-byte header)
        var (tempMilli, unit) = ParseServiceLayerResponse(rspDecrypted);
        string unitName = unit == 0 ? "Celsius" : "Unknown";

        Console.WriteLine($"  RESULT: Temperature = {tempMilli / 1000.0:F3} °{unitName[0]} ({tempMilli} m°C)");
    }
    else
    {
        Console.WriteLine("  No response received.");
    }

    Console.WriteLine("  Stack verified: Ed25519 → Noise XX → AES-GCM → ServiceLayer RPC.");
}