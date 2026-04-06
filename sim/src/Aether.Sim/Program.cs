using System.Buffers.Binary;
using Aether.Core;

// ── Temperature service constants (Spec Part 3 §7) ───────────────────────────

// Service UUID: 00000000-0000-0000-0000-000000000001
static ReadOnlySpan<byte> TempServiceId() =>
    [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1];

const byte   MethodRead     = 0x01;
const byte   FlagRespExpect = 0x01;  // bit 0: response expected
const byte   FlagIsResp     = 0x02;  // bit 1: this is a response
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

// Build the RPC response for Temperature.read.
// CBOR payload: {"t": milliDegrees (i32), "unit": 0}
// Layout: service_id(16) ‖ m_id(1) ‖ call_id(2 BE) ‖ flags(1) ‖ CBOR
static byte[] BuildRpcResponse(int milliDegrees)
{
    // Hand-encoded CBOR map(2):
    //   A2              map(2)
    //   61 74           text(1) "t"
    //   1A xx xx xx xx  uint32
    //   64 75 6E 69 74  text(4) "unit"
    //   00              uint(0)  Celsius
    byte[] cbor = new byte[14];
    cbor[0] = 0xA2;
    cbor[1] = 0x61; cbor[2] = 0x74;
    cbor[3] = 0x1A;
    BinaryPrimitives.WriteInt32BigEndian(cbor.AsSpan(4), milliDegrees);
    cbor[8]  = 0x64;
    cbor[9]  = 0x75; cbor[10] = 0x6E; cbor[11] = 0x69; cbor[12] = 0x74;
    cbor[13] = 0x00;

    byte[] frame = new byte[20 + cbor.Length];
    TempServiceId().CopyTo(frame);
    frame[16] = MethodRead;
    BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(17), CallId);
    frame[19] = FlagIsResp;
    cbor.CopyTo(frame, 20);
    return frame;
}

static (int MilliDegrees, byte Unit) ParseRpcResponse(byte[] payload)
{
    // Skip 20-byte RPC header; CBOR: A2 61 74 1A [4B temp] 64 "unit" [1B unit]
    ReadOnlySpan<byte> cbor = payload.AsSpan(20);
    if (cbor[0] != 0xA2 || cbor[1] != 0x61 || cbor[2] != 0x74 || cbor[3] != 0x1A)
        throw new InvalidDataException("Unexpected CBOR structure in RPC response.");
    int t    = BinaryPrimitives.ReadInt32BigEndian(cbor.Slice(4, 4));
    byte unit = cbor[^1];
    return (t, unit);
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo
// ─────────────────────────────────────────────────────────────────────────────

Console.WriteLine("═══════════════════════════════════════════════════════");
Console.WriteLine("  AETHER PROTOCOL SIMULATOR — End-to-End Demo");
Console.WriteLine("═══════════════════════════════════════════════════════");
Console.WriteLine();

// ── 1. Identity ───────────────────────────────────────────────────────────────

var nodeA = new AetherNode("Node-A");
var nodeB = new AetherNode("Node-B");

Console.WriteLine("── Identity ────────────────────────────────────────────");
foreach (var (node, label) in new[] { (nodeA, "A"), (nodeB, "B") })
{
    Console.WriteLine($"  Node-{label}");
    Console.WriteLine($"    device_id   = {Hex(node.DeviceId)}");
    Console.WriteLine($"    id_pub      = {Hex(node.IdentityPublicKey)}");
    Console.WriteLine($"    static_pub  = {Hex(node.StaticPublicKey)}");
    Console.WriteLine($"    binding_sig = {Hex(node.BindingSig, wrap: 32)}");
    Console.WriteLine();
}

// ── 2. Link layer ─────────────────────────────────────────────────────────────

var link = new LinkLayer();
var epA  = link.EndpointA;
var epB  = link.EndpointB;

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

byte[] keyAtoB  = hsA.SessionKeyToSend!;
byte[] keyBtoA  = hsA.SessionKeyToReceive!;
byte[] nonceIvA = hsA.SessionNonceIV!;

Console.WriteLine($"  session key I→R : {Hex(keyAtoB)}");
Console.WriteLine($"  session key R→I : {Hex(keyBtoA)}");
Console.WriteLine($"  nonce IV        : {Hex(nonceIvA)}");
Console.WriteLine();

bool keysMatch  = keyAtoB.SequenceEqual(hsB.SessionKeyToReceive!)
               && keyBtoA.SequenceEqual(hsB.SessionKeyToSend!)
               && nonceIvA.SequenceEqual(hsB.SessionNonceIV!);

Console.WriteLine(keysMatch
    ? "  [OK] Both sides derived identical session keys and nonce IV."
    : "  [FAIL] Session state mismatch — handshake is broken!");
Console.WriteLine();

if (!keysMatch) return;

// ── 4. RPC: Temperature.read (A calls B) ──────────────────────────────────────

Console.WriteLine("── RPC: Temperature Service — read() ───────────────────");
Console.WriteLine("  Service UUID: 00000000-0000-0000-0000-000000000001");
Console.WriteLine();

// A sends encrypted request (counter=0, I→R direction)
ulong ctrAtoB = 0;
byte[] rpcReqPlain = BuildRpcRequest();
byte[] rpcReqFrame = EncryptDataFrame(keyAtoB, nonceIvA, ctrAtoB, rpcReqPlain);

Console.WriteLine("  [Request]  A → B  (Temperature.read, no args)");
Console.WriteLine($"    plaintext  : {Hex(rpcReqPlain)}");
Console.WriteLine($"    nonce      : {Hex(BuildNonce(nonceIvA, ctrAtoB))}");
Print("  DATA frame", rpcReqFrame);
Console.WriteLine();

await epA.SendAsync(rpcReqFrame);

// B receives, decrypts, inspects
byte[] reqRecv  = await epB.ReceiveAsync();
byte[] reqPlain = DecryptDataFrame(hsB.SessionKeyToReceive!, nonceIvA, ctrAtoB, reqRecv);
Console.WriteLine("  [B received and decrypted]");
Console.WriteLine($"    service_id : {Hex(reqPlain.AsSpan(..16))}");
Console.WriteLine($"    m_id       : 0x{reqPlain[16]:X2}  (read)");
Console.WriteLine($"    call_id    : 0x{BinaryPrimitives.ReadUInt16BigEndian(reqPlain.AsSpan(17)):X4}");
Console.WriteLine($"    flags      : 0x{reqPlain[19]:X2}  (response expected)");
Console.WriteLine();

// B sends encrypted response (counter=0, R→I direction)
const int TempMilliDegrees = 21500;
ulong ctrBtoA = 0;
byte[] rpcRspPlain = BuildRpcResponse(TempMilliDegrees);
byte[] rpcRspFrame = EncryptDataFrame(keyBtoA, nonceIvA, ctrBtoA, rpcRspPlain);

Console.WriteLine($"  [Response]  B → A  (t={TempMilliDegrees} m°C = {TempMilliDegrees / 1000.0:F3}°C, unit=Celsius)");
Console.WriteLine($"    plaintext  : {Hex(rpcRspPlain)}");
Console.WriteLine($"    nonce      : {Hex(BuildNonce(nonceIvA, ctrBtoA))}");
Print("  DATA frame", rpcRspFrame);
Console.WriteLine();

await epB.SendAsync(rpcRspFrame);

// A receives, decrypts, parses result
byte[] rspRecv  = await epA.ReceiveAsync();
byte[] rspPlain = DecryptDataFrame(hsA.SessionKeyToReceive!, nonceIvA, ctrBtoA, rspRecv);
var (t, unit)   = ParseRpcResponse(rspPlain);
string unitName = unit switch { 0 => "Celsius", 1 => "Fahrenheit", 2 => "Kelvin", _ => $"unit={unit}" };

Console.WriteLine("═══════════════════════════════════════════════════════");
Console.WriteLine($"  RESULT: Temperature = {t / 1000.0:F3} °{unitName[0]}  ({t} m°C)");
Console.WriteLine("  Stack verified: Ed25519 identity → binding → Noise XX → AES-GCM RPC.");
Console.WriteLine("═══════════════════════════════════════════════════════");

link.Close();
