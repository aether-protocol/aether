using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace Aether.Core;

/// <summary>
/// Cryptographic primitives for the Aether protocol.
/// Spec §1: Ed25519 identity keys, X25519 ECDH, HKDF-SHA256 key derivation,
/// AES-256-GCM authenticated encryption.
/// </summary>
public static class Crypto
{
    private const int TagSize = 16;

    /// <summary>
    /// Generates an Ed25519 long-term identity keypair.
    /// Returns (privateKey, publicKey) as raw 32-byte arrays.
    /// The device address is derived from the public key via <see cref="DeriveDeviceId"/>.
    /// </summary>
    public static (byte[] PrivateKey, byte[] PublicKey) GenerateIdentityKeypair()
    {
        using var key = Key.Create(
            SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return (
            key.Export(KeyBlobFormat.RawPrivateKey),
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>
    /// Generates an X25519 ephemeral keypair for use in Diffie-Hellman key exchange.
    /// Returns (privateKey, publicKey) as raw 32-byte arrays.
    /// Ephemeral keys MUST NOT be reused across sessions.
    /// </summary>
    public static (byte[] PrivateKey, byte[] PublicKey) GenerateEphemeralKeypair()
    {
        using var key = Key.Create(
            KeyAgreementAlgorithm.X25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        return (
            key.Export(KeyBlobFormat.RawPrivateKey),
            key.PublicKey.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>
    /// Computes the SHA3-256 hash of <paramref name="data"/>, returning all 32 bytes.
    /// </summary>
    public static byte[] Sha3Hash256(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var digest = new Sha3Digest(256);
        digest.BlockUpdate(data, 0, data.Length);
        byte[] hash = new byte[32];
        digest.DoFinal(hash, 0);
        return hash;
    }

    /// <summary>
    /// Derives a 6-byte device address from an Ed25519 public key.
    /// DeviceId = SHA3-256(publicKey)[0:6]  (Spec §1.2)
    /// </summary>
    public static byte[] DeriveDeviceId(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        return Sha3Hash256(publicKey)[..6];
    }

    /// <summary>
    /// Performs an X25519 Diffie-Hellman key exchange, returning the 32-byte shared secret.
    /// NSec intentionally wraps SharedSecret opaquely, so BouncyCastle is used here
    /// to expose the raw DH output required by the Noise XX handshake (Spec §1.3).
    /// </summary>
    public static byte[] X25519KeyExchange(byte[] privateKey, byte[] peerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(peerPublicKey);

        try
        {
            // RFC 7748 §5: always clamp the private scalar before use.
            // We clamp a copy so we never mutate the caller's array.
            byte[] scalar = ClampX25519Scalar(privateKey);
            var agreement = new X25519Agreement();
            agreement.Init(new X25519PrivateKeyParameters(scalar));
            byte[] secret = new byte[32];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublicKey), secret, 0);
            return secret;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new CryptographicException("X25519 key exchange failed.", ex);
        }
    }

    /// <summary>
    /// Derives keying material using HKDF-SHA256 (RFC 5869).
    /// A null or empty <paramref name="salt"/> is treated as a zero-filled byte array
    /// of hash length, per the RFC.
    /// </summary>
    public static byte[] HkdfDerive(byte[] ikm, byte[]? salt, string info, int outputLength) =>
        HkdfDerive(ikm, salt, string.IsNullOrEmpty(info) ? [] : Encoding.UTF8.GetBytes(info), outputLength);

    /// <summary>
    /// Internal overload accepting raw <paramref name="infoBytes"/> — used for RFC 5869 test vectors
    /// where the info field is binary rather than a UTF-8 string.
    /// </summary>
    internal static byte[] HkdfDerive(byte[] ikm, byte[]? salt, byte[] infoBytes, int outputLength)
    {
        ArgumentNullException.ThrowIfNull(ikm);
        ArgumentNullException.ThrowIfNull(infoBytes);
        if (outputLength <= 0 || outputLength > 255 * 32)
            throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be between 1 and 8160 bytes.");

        // Extract: PRK = HMAC-SHA256(salt, IKM)
        byte[] effectiveSalt = (salt is null || salt.Length == 0) ? new byte[32] : salt;
        byte[] prk;
        using (var hmac = new HMACSHA256(effectiveSalt))
            prk = hmac.ComputeHash(ikm);

        // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        int blocks = (outputLength + 31) / 32;
        byte[] okm = new byte[blocks * 32];
        byte[] t = [];
        for (int i = 1; i <= blocks; i++)
        {
            using var hmac = new HMACSHA256(prk);
            t = hmac.ComputeHash([.. t, .. infoBytes, (byte)i]);
            t.CopyTo(okm, (i - 1) * 32);
        }
        return okm[..outputLength];
    }

    /// <summary>
    /// Encrypts plaintext with AES-256-GCM.
    /// Returns ciphertext with the 16-byte authentication tag appended.
    /// </summary>
    /// <param name="key">32-byte AES-256 key.</param>
    /// <param name="nonce">12-byte nonce. Must never be reused with the same key.</param>
    /// <param name="aad">Additional authenticated data (may be null).</param>
    public static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[]? aad)
    {
        ValidateAesParams(key, nonce);
        ArgumentNullException.ThrowIfNull(plaintext);

        try
        {
            using var aesGcm = new AesGcm(key, TagSize);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            return [.. ciphertext, .. tag];
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new CryptographicException("AES-GCM encryption failed.", ex);
        }
    }

    /// <summary>
    /// Decrypts and authenticates AES-256-GCM ciphertext.
    /// Expects <paramref name="ciphertextWithTag"/> to contain the ciphertext
    /// followed by the 16-byte authentication tag produced by <see cref="AesGcmEncrypt"/>.
    /// Throws <see cref="CryptographicException"/> if authentication fails.
    /// </summary>
    /// <param name="key">32-byte AES-256 key.</param>
    /// <param name="nonce">12-byte nonce matching the one used during encryption.</param>
    /// <param name="aad">Additional authenticated data (may be null).</param>
    public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[]? aad)
    {
        ValidateAesParams(key, nonce);
        ArgumentNullException.ThrowIfNull(ciphertextWithTag);

        if (ciphertextWithTag.Length < TagSize)
            throw new CryptographicException("Ciphertext is too short to contain an authentication tag.");

        try
        {
            using var aesGcm = new AesGcm(key, TagSize);
            int ctLen = ciphertextWithTag.Length - TagSize;
            byte[] plaintext = new byte[ctLen];
            aesGcm.Decrypt(
                nonce,
                ciphertextWithTag.AsSpan(0, ctLen),
                ciphertextWithTag.AsSpan(ctLen),
                plaintext,
                aad);
            return plaintext;
        }
        catch (CryptographicException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new CryptographicException("AES-GCM decryption failed.", ex);
        }
    }

    /// <summary>
    /// Signs <paramref name="message"/> with an Ed25519 private key (Spec §4.1.1).
    /// Returns the 64-byte signature.
    /// </summary>
    public static byte[] Ed25519Sign(byte[] privateKey, byte[] message)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(message);
        try
        {
            using var key = Key.Import(
                SignatureAlgorithm.Ed25519, privateKey, KeyBlobFormat.RawPrivateKey);
            return SignatureAlgorithm.Ed25519.Sign(key, message);
        }
        catch (CryptographicException) { throw; }
        catch (Exception ex) { throw new CryptographicException("Ed25519 sign failed.", ex); }
    }

    /// <summary>
    /// Verifies an Ed25519 <paramref name="signature"/> over <paramref name="message"/>.
    /// Throws <see cref="CryptographicException"/> if the signature is invalid.
    /// </summary>
    public static void Ed25519Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);
        try
        {
            var key = PublicKey.Import(
                SignatureAlgorithm.Ed25519, publicKey, KeyBlobFormat.RawPublicKey);
            if (!SignatureAlgorithm.Ed25519.Verify(key, message, signature))
                throw new CryptographicException("Ed25519 signature verification failed.");
        }
        catch (CryptographicException) { throw; }
        catch (Exception ex) { throw new CryptographicException("Ed25519 verify failed.", ex); }
    }

    /// <summary>
    /// Applies RFC 7748 §5 X25519 scalar clamping to a copy of <paramref name="scalar"/>.
    /// Clears the three lowest bits of byte[0], clears the highest bit of byte[31],
    /// and sets the second-highest bit of byte[31].
    /// </summary>
    private static byte[] ClampX25519Scalar(byte[] scalar)
    {
        byte[] clamped = (byte[])scalar.Clone();
        clamped[0]  &= 0xF8;          // clear bits 0, 1, 2
        clamped[31] &= 0x7F;          // clear bit 255
        clamped[31] |= 0x40;          // set bit 254
        return clamped;
    }

    private static void ValidateAesParams(byte[] key, byte[] nonce)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new CryptographicException("AES-256 requires a 32-byte key.");
        ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length != 12)
            throw new CryptographicException("AES-GCM requires a 12-byte nonce.");
    }
}
