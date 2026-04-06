using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Aether.Core;

/// <summary>
/// Authenticated, encrypted data channel for a single session direction (Spec §7).
/// Wraps AES-256-GCM with the nonce construction and replay-protection counter
/// required by the spec.
/// </summary>
/// <remarks>
/// One <see cref="SessionChannel"/> covers one direction (e.g. I→R).
/// Create two per session — one for each direction — using the keys and nonce IV
/// produced by <see cref="HandshakeInitiator"/> or <see cref="HandshakeResponder"/>.
/// <para/>
/// Nonce construction (Spec §7.1):
/// <c>nonce = fixed_iv XOR encode64(counter)</c>
/// where <c>encode64</c> is the 8-byte little-endian counter zero-padded to 12 bytes.
/// </remarks>
public sealed class SessionChannel
{
    private readonly byte[] _key;
    private readonly byte[] _nonceIv;  // 12-byte per-session fixed IV from key material

    private ulong _txCounter;
    private ulong _rxCounter = ulong.MaxValue; // sentinel: nothing received yet

    public SessionChannel(byte[] key, byte[] nonceIv)
    {
        if (key is null || key.Length != 32)
            throw new CryptographicException("Session key must be 32 bytes.");
        if (nonceIv is null || nonceIv.Length != 12)
            throw new CryptographicException("Nonce IV must be 12 bytes.");
        _key     = key;
        _nonceIv = nonceIv;
    }

    /// <summary>Number of frames encrypted on the send side.</summary>
    public ulong TxCounter => _txCounter;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and returns a DATA frame.
    /// Frame layout: counter(8 B LE) ‖ ciphertext ‖ tag(16 B).
    /// The 8-byte counter header is used as AAD, binding it to the authentication tag.
    /// </summary>
    public byte[] Encrypt(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        ulong counter = _txCounter++;
        byte[] header = BuildHeader(counter);
        byte[] nonce  = BuildNonce(counter);
        byte[] ct     = Crypto.AesGcmEncrypt(_key, nonce, plaintext, header);
        return [.. header, .. ct];
    }

    /// <summary>
    /// Decrypts and authenticates a DATA frame produced by <see cref="Encrypt"/>.
    /// Enforces monotone counter ordering: any frame whose counter is not strictly
    /// greater than the last accepted counter is silently dropped by throwing
    /// <see cref="CryptographicException"/> (Spec §7.1 replay protection).
    /// </summary>
    /// <exception cref="CryptographicException">
    /// Thrown on authentication failure or replay-protection violation.
    /// </exception>
    public byte[] Decrypt(byte[] frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Length < 8 + 16)
            throw new CryptographicException("Frame too short to contain header and GCM tag.");

        byte[] header  = frame[..8];
        byte[] ctAndTag = frame[8..];
        ulong  counter = BinaryPrimitives.ReadUInt64LittleEndian(header);

        // Replay protection: counter must be strictly increasing.
        // On the very first frame _rxCounter is ulong.MaxValue (sentinel),
        // so any counter value (including 0) passes.
        if (_rxCounter != ulong.MaxValue && counter <= _rxCounter)
            throw new CryptographicException(
                $"Replay detected: received counter {counter} ≤ last accepted {_rxCounter}.");

        byte[] nonce = BuildNonce(counter);
        // AesGcmDecrypt throws CryptographicException on tag mismatch.
        byte[] plaintext = Crypto.AesGcmDecrypt(_key, nonce, ctAndTag, header);

        _rxCounter = counter;
        return plaintext;
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    internal static byte[] BuildNonce(byte[] fixedIv, ulong counter)
    {
        Span<byte> encoded = stackalloc byte[12]; // zero-padded
        BinaryPrimitives.WriteUInt64LittleEndian(encoded, counter);
        byte[] nonce = new byte[12];
        for (int i = 0; i < 12; i++)
            nonce[i] = (byte)(fixedIv[i] ^ encoded[i]);
        return nonce;
    }

    private byte[] BuildNonce(ulong counter) => BuildNonce(_nonceIv, counter);

    private static byte[] BuildHeader(ulong counter)
    {
        byte[] h = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(h, counter);
        return h;
    }
}
