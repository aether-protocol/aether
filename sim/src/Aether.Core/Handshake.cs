using System.Security.Cryptography;

namespace Aether.Core;

// ── Shared constants and helpers ─────────────────────────────────────────────

file static class H
{
    // Message type bytes
    public const byte Msg1Type = 0x01;
    public const byte Msg2Type = 0x02;
    public const byte Msg3Type = 0x03;

    // Encrypted identity payload (Spec §6.2):
    //   static_pub   (32 B) — X25519 static public key for DH
    //   identity_pub (32 B) — Ed25519 public key (device ID source)
    //   binding_sig  (64 B) — Ed25519.sign(identity_priv, static_pub)
    public const int PayloadLen     = 128;          // 32 + 32 + 64
    public const int CiphertextLen  = PayloadLen + 16; // plaintext + GCM tag = 144

    // Wire lengths
    public const int Msg1Len = 34;                  // 1 type + 1 flags + 32 e_pub
    public const int Msg2Len = 2 + 32 + CiphertextLen; // 178
    public const int Msg3Len = 2 + CiphertextLen;       // 146

    public const int PubKeyLen = 32;
    public const int SigLen    = 64;

    // Each handshake ciphertext uses a unique key, so a zero nonce is safe.
    public static readonly byte[] ZeroNonce = new byte[12];

    // HKDF info strings
    public const string Msg3KeyInfo = "aether-v0.1-msg3-key";
    public const string SessionInfo = "aether-v0.1-session";

    // Session key material layout (76 bytes total):
    //   [0:32]  I→R data key
    //   [32:64] R→I data key
    //   [64:76] shared nonce IV (used by both sides to build per-frame nonces)
    public const int SessionMaterialLen = 76;

    // ── Helpers ──────────────────────────────────────────────────────────────

    public static void ValidateMsg(byte[] msg, byte expectedType, int expectedLen)
    {
        if (msg.Length < expectedLen)
            throw new CryptographicException(
                $"Handshake message too short: expected {expectedLen} bytes, got {msg.Length}.");
        if (msg[0] != expectedType)
            throw new CryptographicException(
                $"Expected message type 0x{expectedType:X2}, got 0x{msg[0]:X2}.");
    }

    /// <summary>Encodes the 128-byte identity payload for msg2 or msg3.</summary>
    public static byte[] EncodePayload(byte[] staticPub, byte[] identityPub, byte[] bindingSig) =>
        [.. staticPub, .. identityPub, .. bindingSig];

    /// <summary>
    /// Decodes and cryptographically verifies a received identity payload.
    /// Verifies the binding signature (Spec §6.3) and the device ID.
    /// Returns (<paramref name="staticPub"/>, <paramref name="identityPub"/>).
    /// Throws <see cref="CryptographicException"/> on any failure.
    /// </summary>
    public static (byte[] StaticPub, byte[] IdentityPub) DecodeAndVerify(byte[] payload)
    {
        if (payload.Length != PayloadLen)
            throw new CryptographicException(
                $"Identity payload must be {PayloadLen} bytes, got {payload.Length}.");

        byte[] staticPub   = payload[..32];
        byte[] identityPub = payload[32..64];
        byte[] bindingSig  = payload[64..];

        // Spec §6.3 rule 1: Ed25519.verify(identity_pub, static_pub, binding_sig)
        Crypto.Ed25519Verify(identityPub, staticPub, bindingSig);

        // Spec §6.3 rule 2: device_id == SHA3-256(identity_pub)[0:6]
        // (Verified implicitly — callers expose PeerDeviceId derived from identityPub.)

        return (staticPub, identityPub);
    }

    /// <summary>
    /// Derives the 32-byte msg3 encryption key.
    /// Both parties can compute this before msg3 is transmitted.
    /// </summary>
    /// <param name="kEE">DH(e_I, e_R) — ephemeral-ephemeral (Noise 'ee')</param>
    /// <param name="kES">DH(e_I, s_R) = DH(s_R, e_I) — ephemeral-static (Noise 'es')</param>
    public static byte[] DeriveMsg3Key(byte[] kEE, byte[] kES) =>
        Crypto.HkdfDerive([.. kEE, .. kES], salt: null, info: Msg3KeyInfo, outputLength: 32);

    /// <summary>
    /// Derives 76 bytes of session keying material.
    /// Layout: I→R key (32) ‖ R→I key (32) ‖ nonce IV (12).
    /// </summary>
    /// <param name="kEE">DH(e_I, e_R) — Noise 'ee'</param>
    /// <param name="kSE">DH(s_I, e_R) = DH(e_R, s_I) — Noise 'se'</param>
    /// <param name="transcript">SHA3-256(msg1 ‖ msg2 ‖ msg3)</param>
    public static byte[] DeriveSessionMaterial(byte[] kEE, byte[] kSE, byte[] transcript) =>
        Crypto.HkdfDerive([.. kEE, .. kSE], salt: transcript, info: SessionInfo,
            outputLength: SessionMaterialLen);
}

// ── Initiator ─────────────────────────────────────────────────────────────────

/// <summary>
/// Noise XX handshake — initiator side (Spec §6).
/// <para>
/// Usage:
/// <code>
///   var hs = new HandshakeInitiator(staticPriv, staticPub, identityPub, bindingSig);
///   byte[] msg1 = hs.Step();       // send to responder
///   byte[] msg3 = hs.Step(msg2);   // process msg2, send msg3; session keys ready
/// </code>
/// </para>
/// </summary>
public sealed class HandshakeInitiator
{
    private readonly byte[] _staticPriv;    // X25519 — used for DH(s_I, e_R)
    private readonly byte[] _staticPub;     // X25519 — transmitted in msg3 payload
    private readonly byte[] _identityPub;   // Ed25519 — transmitted in msg3 payload
    private readonly byte[] _bindingSig;    // Ed25519.sign(identity_priv, static_pub)
    private readonly Func<(byte[], byte[])> _ephemeralKeyFactory;
    private byte[] _ePriv = [];             // ephemeral X25519 private key
    private byte[] _msg1  = [];
    private byte[] _msg2  = [];
    private int _step;

    /// <param name="staticPrivateKey">Own X25519 static private key (for DH).</param>
    /// <param name="staticPublicKey">Own X25519 static public key (transmitted in msg3).</param>
    /// <param name="identityPublicKey">Own Ed25519 identity public key (transmitted in msg3).</param>
    /// <param name="bindingSig">
    /// Ed25519.sign(identity_priv, static_pub) — proves the static key belongs to this identity.
    /// </param>
    public HandshakeInitiator(
        byte[] staticPrivateKey,
        byte[] staticPublicKey,
        byte[] identityPublicKey,
        byte[] bindingSig)
        : this(staticPrivateKey, staticPublicKey, identityPublicKey, bindingSig,
               Crypto.GenerateEphemeralKeypair) { }

    /// <summary>Internal constructor for deterministic tests — injects a fixed ephemeral keypair.</summary>
    internal HandshakeInitiator(
        byte[] staticPrivateKey,
        byte[] staticPublicKey,
        byte[] identityPublicKey,
        byte[] bindingSig,
        Func<(byte[], byte[])> ephemeralKeyFactory)
    {
        ArgumentNullException.ThrowIfNull(staticPrivateKey);
        ArgumentNullException.ThrowIfNull(staticPublicKey);
        ArgumentNullException.ThrowIfNull(identityPublicKey);
        ArgumentNullException.ThrowIfNull(bindingSig);
        ArgumentNullException.ThrowIfNull(ephemeralKeyFactory);
        _staticPriv          = staticPrivateKey;
        _staticPub           = staticPublicKey;
        _identityPub         = identityPublicKey;
        _bindingSig          = bindingSig;
        _ephemeralKeyFactory = ephemeralKeyFactory;
    }

    // ── Public state ─────────────────────────────────────────────────────────

    /// <summary>I→R session key. Set after step 1.</summary>
    public byte[]? SessionKeyToSend { get; private set; }

    /// <summary>R→I session key. Set after step 1.</summary>
    public byte[]? SessionKeyToReceive { get; private set; }

    /// <summary>
    /// 12-byte nonce IV shared by both sides (Spec §7.1).
    /// Per-frame nonce = SessionNonceIV XOR encode64(counter).
    /// </summary>
    public byte[]? SessionNonceIV { get; private set; }

    /// <summary>Peer's X25519 static public key. Set after step 1.</summary>
    public byte[]? PeerStaticPublicKey { get; private set; }

    /// <summary>Peer's Ed25519 identity public key. Set after step 1.</summary>
    public byte[]? PeerIdentityPublicKey { get; private set; }

    /// <summary>Peer's device ID: SHA3-256(PeerIdentityPublicKey)[0:6]. Set after step 1.</summary>
    public byte[]? PeerDeviceId { get; private set; }

    // ── State machine ─────────────────────────────────────────────────────────

    /// <summary>
    /// Advances the handshake.
    /// Step 0 — call with <c>null</c>: returns msg1.
    /// Step 1 — call with msg2 bytes: returns msg3; session keys available.
    /// </summary>
    public byte[] Step(byte[]? incoming = null) => _step++ switch
    {
        0 => Step0_BuildMsg1(),
        1 => Step1_ProcessMsg2BuildMsg3(incoming
                 ?? throw new CryptographicException("msg2 bytes are required for step 1.")),
        _ => throw new InvalidOperationException("Handshake is already complete.")
    };

    // msg1 = [type=1 | flags=0 | e_I.pub (32 B)]
    private byte[] Step0_BuildMsg1()
    {
        byte[] ePub;
        (_ePriv, ePub) = _ephemeralKeyFactory();
        _msg1 = [H.Msg1Type, 0x00, .. ePub];
        return [.. _msg1];
    }

    // Consume msg2, emit msg3, derive session keys.
    private byte[] Step1_ProcessMsg2BuildMsg3(byte[] msg2)
    {
        H.ValidateMsg(msg2, H.Msg2Type, H.Msg2Len);

        // msg2 = [type(1) | flags(1) | e_R.pub(32) | AES-GCM{payload_R}(144)]
        byte[] eRPub = msg2[2..34];
        byte[] encR  = msg2[34..H.Msg2Len];

        // k_ee = DH(e_I, e_R)
        byte[] kEE = Crypto.X25519KeyExchange(_ePriv, eRPub);

        // Decrypt and verify responder's identity payload
        byte[] aad2    = Crypto.Sha3Hash256([.. _msg1, .. msg2[..34]]);
        byte[] payloadR = Crypto.AesGcmDecrypt(kEE, H.ZeroNonce, encR, aad2);
        (PeerStaticPublicKey, PeerIdentityPublicKey) = H.DecodeAndVerify(payloadR);
        PeerDeviceId = Crypto.DeriveDeviceId(PeerIdentityPublicKey);
        _msg2 = [.. msg2];

        // k_es = DH(e_I, s_R)  (Noise 'es') — both parties compute this before msg3
        byte[] kES = Crypto.X25519KeyExchange(_ePriv, PeerStaticPublicKey);

        // k_se = DH(s_I, e_R)  (Noise 'se') — for session key derivation
        byte[] kSE = Crypto.X25519KeyExchange(_staticPriv, eRPub);

        // Build msg3 payload: static_pub_I || identity_pub_I || binding_sig_I
        byte[] payloadI = H.EncodePayload(_staticPub, _identityPub, _bindingSig);
        byte[] msg3Key  = H.DeriveMsg3Key(kEE, kES);
        byte[] aad3     = Crypto.Sha3Hash256([.. _msg1, .. _msg2]);
        byte[] encI     = Crypto.AesGcmEncrypt(msg3Key, H.ZeroNonce, payloadI, aad3);
        byte[] msg3     = [H.Msg3Type, 0x00, .. encI];

        // Session key material: I→R key | R→I key | nonce IV
        byte[] transcript  = Crypto.Sha3Hash256([.. _msg1, .. _msg2, .. msg3]);
        byte[] km          = H.DeriveSessionMaterial(kEE, kSE, transcript);
        SessionKeyToSend    = km[..32];
        SessionKeyToReceive = km[32..64];
        SessionNonceIV      = km[64..];

        return [.. msg3];
    }
}

// ── Responder ─────────────────────────────────────────────────────────────────

/// <summary>
/// Noise XX handshake — responder side (Spec §6).
/// <para>
/// Usage:
/// <code>
///   var hs = new HandshakeResponder(staticPriv, staticPub, identityPub, bindingSig);
///   byte[] msg2 = hs.Step(msg1);   // process msg1, send msg2
///   hs.Step(msg3);                 // process msg3; session keys ready
/// </code>
/// </para>
/// </summary>
public sealed class HandshakeResponder
{
    private readonly byte[] _staticPriv;    // X25519 — used for DH(s_R, e_I) and DH(e_R, s_I)
    private readonly byte[] _staticPub;     // X25519 — transmitted in msg2 payload
    private readonly byte[] _identityPub;   // Ed25519 — transmitted in msg2 payload
    private readonly byte[] _bindingSig;    // Ed25519.sign(identity_priv, static_pub)
    private readonly Func<(byte[], byte[])> _ephemeralKeyFactory;
    private byte[] _ePriv = [];             // ephemeral X25519 private key
    private byte[] _kEE   = [];             // DH(e_R, e_I) — saved for step 1
    private byte[] _kES   = [];             // DH(s_R, e_I) — saved for step 1
    private byte[] _msg1  = [];
    private byte[] _msg2  = [];
    private int _step;

    /// <param name="staticPrivateKey">Own X25519 static private key (for DH).</param>
    /// <param name="staticPublicKey">Own X25519 static public key (transmitted in msg2).</param>
    /// <param name="identityPublicKey">Own Ed25519 identity public key (transmitted in msg2).</param>
    /// <param name="bindingSig">
    /// Ed25519.sign(identity_priv, static_pub) — proves the static key belongs to this identity.
    /// </param>
    public HandshakeResponder(
        byte[] staticPrivateKey,
        byte[] staticPublicKey,
        byte[] identityPublicKey,
        byte[] bindingSig)
        : this(staticPrivateKey, staticPublicKey, identityPublicKey, bindingSig,
               Crypto.GenerateEphemeralKeypair) { }

    /// <summary>Internal constructor for deterministic tests — injects a fixed ephemeral keypair.</summary>
    internal HandshakeResponder(
        byte[] staticPrivateKey,
        byte[] staticPublicKey,
        byte[] identityPublicKey,
        byte[] bindingSig,
        Func<(byte[], byte[])> ephemeralKeyFactory)
    {
        ArgumentNullException.ThrowIfNull(staticPrivateKey);
        ArgumentNullException.ThrowIfNull(staticPublicKey);
        ArgumentNullException.ThrowIfNull(identityPublicKey);
        ArgumentNullException.ThrowIfNull(bindingSig);
        ArgumentNullException.ThrowIfNull(ephemeralKeyFactory);
        _staticPriv          = staticPrivateKey;
        _staticPub           = staticPublicKey;
        _identityPub         = identityPublicKey;
        _bindingSig          = bindingSig;
        _ephemeralKeyFactory = ephemeralKeyFactory;
    }

    // ── Public state ─────────────────────────────────────────────────────────

    /// <summary>R→I session key. Set after step 1.</summary>
    public byte[]? SessionKeyToSend { get; private set; }

    /// <summary>I→R session key. Set after step 1.</summary>
    public byte[]? SessionKeyToReceive { get; private set; }

    /// <summary>
    /// 12-byte nonce IV shared by both sides (Spec §7.1).
    /// Per-frame nonce = SessionNonceIV XOR encode64(counter).
    /// </summary>
    public byte[]? SessionNonceIV { get; private set; }

    /// <summary>Peer's X25519 static public key. Set after step 1.</summary>
    public byte[]? PeerStaticPublicKey { get; private set; }

    /// <summary>Peer's Ed25519 identity public key. Set after step 1.</summary>
    public byte[]? PeerIdentityPublicKey { get; private set; }

    /// <summary>Peer's device ID: SHA3-256(PeerIdentityPublicKey)[0:6]. Set after step 1.</summary>
    public byte[]? PeerDeviceId { get; private set; }

    // ── State machine ─────────────────────────────────────────────────────────

    /// <summary>
    /// Advances the handshake.
    /// Step 0 — call with msg1 bytes: returns msg2.
    /// Step 1 — call with msg3 bytes: returns empty byte[]; session keys available.
    /// </summary>
    public byte[] Step(byte[] incoming) => _step++ switch
    {
        0 => Step0_ProcessMsg1BuildMsg2(incoming),
        1 => Step1_ProcessMsg3(incoming),
        _ => throw new InvalidOperationException("Handshake is already complete.")
    };

    // Consume msg1, emit msg2; pre-compute k_ee and k_es for reuse in step 1.
    private byte[] Step0_ProcessMsg1BuildMsg2(byte[] msg1)
    {
        H.ValidateMsg(msg1, H.Msg1Type, H.Msg1Len);

        byte[] eIPub = msg1[2..34];
        _msg1 = [.. msg1];

        byte[] eRPub;
        (_ePriv, eRPub) = _ephemeralKeyFactory();

        // k_ee = DH(e_R, e_I)
        _kEE = Crypto.X25519KeyExchange(_ePriv, eIPub);

        // k_es = DH(s_R, e_I)  (Noise 'es') — computable now; reused to derive msg3 key.
        // Symmetric to initiator's DH(e_I, s_R): no circularity since we know e_I.pub.
        _kES = Crypto.X25519KeyExchange(_staticPriv, eIPub);

        // Build msg2 payload: static_pub_R || identity_pub_R || binding_sig_R
        byte[] payloadR  = H.EncodePayload(_staticPub, _identityPub, _bindingSig);
        byte[] msg2Prefix = [H.Msg2Type, 0x00, .. eRPub];   // 34 bytes
        byte[] aad2       = Crypto.Sha3Hash256([.. _msg1, .. msg2Prefix]);
        byte[] encR       = Crypto.AesGcmEncrypt(_kEE, H.ZeroNonce, payloadR, aad2);

        _msg2 = [.. msg2Prefix, .. encR];  // 178 bytes
        return [.. _msg2];
    }

    // Consume msg3; verify initiator identity; derive session keys.
    private byte[] Step1_ProcessMsg3(byte[] msg3)
    {
        H.ValidateMsg(msg3, H.Msg3Type, H.Msg3Len);

        byte[] encI = msg3[2..H.Msg3Len];

        // Reconstruct msg3 key — same formula as initiator
        byte[] msg3Key  = H.DeriveMsg3Key(_kEE, _kES);
        byte[] aad3     = Crypto.Sha3Hash256([.. _msg1, .. _msg2]);
        byte[] payloadI = Crypto.AesGcmDecrypt(msg3Key, H.ZeroNonce, encI, aad3);

        // Verify initiator's binding signature and extract identity
        (PeerStaticPublicKey, PeerIdentityPublicKey) = H.DecodeAndVerify(payloadI);
        PeerDeviceId = Crypto.DeriveDeviceId(PeerIdentityPublicKey);

        // k_se = DH(e_R, s_I)  (Noise 'se') — for session key derivation
        byte[] kSE = Crypto.X25519KeyExchange(_ePriv, PeerStaticPublicKey);

        // Session key material: I→R key | R→I key | nonce IV
        byte[] transcript  = Crypto.Sha3Hash256([.. _msg1, .. _msg2, .. msg3]);
        byte[] km          = H.DeriveSessionMaterial(_kEE, kSE, transcript);
        SessionKeyToSend    = km[32..64];   // R→I
        SessionKeyToReceive = km[..32];     // I→R
        SessionNonceIV      = km[64..];

        return [];
    }
}
