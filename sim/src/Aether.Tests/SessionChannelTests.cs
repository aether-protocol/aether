using System.Security.Cryptography;
using Aether.Core;
using Xunit;

namespace Aether.Tests;

/// <summary>
/// Tests for <see cref="SessionChannel"/> — nonce construction, frame layout,
/// AES-GCM authentication, and replay protection (Spec §7).
/// </summary>
public class SessionChannelTests
{
    private static readonly byte[] Key    = new byte[32]; // all-zero test key
    private static readonly byte[] NonceIv = new byte[12]; // all-zero IV

    private static SessionChannel MakeTx() => new(Key, NonceIv);
    private static SessionChannel MakeRx() => new(Key, NonceIv);

    // ── Nonce construction ────────────────────────────────────────────────────

    [Fact]
    public void BuildNonce_Counter0_AllZeroIv_YieldsAllZero()
    {
        // IV=0, counter=0 → nonce = 0 XOR 0 = 0
        byte[] n = SessionChannel.BuildNonce(new byte[12], 0UL);
        Assert.Equal(new byte[12], n);
    }

    [Fact]
    public void BuildNonce_Counter1_SetsBitInNonce()
    {
        // encode64(1) = [01 00 00 00 00 00 00 00 00 00 00 00]
        byte[] n = SessionChannel.BuildNonce(new byte[12], 1UL);
        Assert.Equal(0x01, n[0]);
        Assert.Equal(0x00, n[1]);
    }

    [Fact]
    public void BuildNonce_NonZeroIv_XoredWithCounter()
    {
        byte[] iv = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00];
        // counter=1 → encode64(1)[0]=0x01, XOR 0xFF = 0xFE
        byte[] n = SessionChannel.BuildNonce(iv, 1UL);
        Assert.Equal(0xFE, n[0]);
    }

    [Fact]
    public void BuildNonce_SameCounterDifferentIv_ProducesDifferentNonces()
    {
        byte[] iv1 = new byte[12];
        byte[] iv2 = new byte[12]; iv2[0] = 0xAB;
        byte[] n1 = SessionChannel.BuildNonce(iv1, 42UL);
        byte[] n2 = SessionChannel.BuildNonce(iv2, 42UL);
        Assert.NotEqual(Convert.ToHexString(n1), Convert.ToHexString(n2));
    }

    // ── Frame layout ──────────────────────────────────────────────────────────

    [Fact]
    public void Encrypt_Frame_StartsWithLittleEndianCounter()
    {
        var tx       = MakeTx();
        byte[] frame = tx.Encrypt([1, 2, 3]);
        // First 8 bytes = counter 0 in LE
        ulong counter = BitConverter.ToUInt64(frame, 0);
        Assert.Equal(0UL, counter);
    }

    [Fact]
    public void Encrypt_SecondFrame_CounterIs1()
    {
        var tx = MakeTx();
        tx.Encrypt([1]);
        byte[] frame  = tx.Encrypt([2]);
        ulong counter = BitConverter.ToUInt64(frame, 0);
        Assert.Equal(1UL, counter);
    }

    [Fact]
    public void Encrypt_FrameLength_IsHeaderPlusPlaintextPlusTag()
    {
        var tx       = MakeTx();
        byte[] plain = [10, 20, 30, 40];
        byte[] frame = tx.Encrypt(plain);
        Assert.Equal(8 + plain.Length + 16, frame.Length);
    }

    [Fact]
    public void Encrypt_TxCounterIncrements()
    {
        var tx = MakeTx();
        Assert.Equal(0UL, tx.TxCounter);
        tx.Encrypt([1]);
        Assert.Equal(1UL, tx.TxCounter);
        tx.Encrypt([2]);
        Assert.Equal(2UL, tx.TxCounter);
    }

    // ── Encrypt / Decrypt round-trip ──────────────────────────────────────────

    [Fact]
    public void EncryptDecrypt_SingleFrame_RecoversMplaintext()
    {
        var tx    = MakeTx();
        var rx    = MakeRx();
        byte[] pt = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] frame = tx.Encrypt(pt);
        byte[] got   = rx.Decrypt(frame);
        Assert.Equal(Convert.ToHexString(pt), Convert.ToHexString(got));
    }

    [Fact]
    public void EncryptDecrypt_MultipleFrames_AllDecryptCorrectly()
    {
        var tx = MakeTx();
        var rx = MakeRx();
        for (int i = 0; i < 10; i++)
        {
            byte[] pt    = [(byte)i, (byte)(i * 2)];
            byte[] got   = rx.Decrypt(tx.Encrypt(pt));
            Assert.Equal(Convert.ToHexString(pt), Convert.ToHexString(got));
        }
    }

    [Fact]
    public void EncryptDecrypt_EmptyPlaintext_Allowed()
    {
        var tx = MakeTx();
        var rx = MakeRx();
        byte[] got = rx.Decrypt(tx.Encrypt([]));
        Assert.Empty(got);
    }

    [Fact]
    public void EncryptDecrypt_LargePayload_RoundTrips()
    {
        var tx    = MakeTx();
        var rx    = MakeRx();
        byte[] pt = new byte[512];
        new Random(42).NextBytes(pt);
        byte[] got = rx.Decrypt(tx.Encrypt(pt));
        Assert.Equal(Convert.ToHexString(pt), Convert.ToHexString(got));
    }

    // ── Authentication ────────────────────────────────────────────────────────

    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        var tx    = MakeTx();
        var rx    = MakeRx();
        byte[] frame = tx.Encrypt([1, 2, 3]);
        frame[8] ^= 0xFF; // flip a byte in the ciphertext
        // AuthenticationTagMismatchException is a subclass of CryptographicException
        Assert.ThrowsAny<CryptographicException>(() => rx.Decrypt(frame));
    }

    [Fact]
    public void Decrypt_TamperedTag_ThrowsCryptographicException()
    {
        var tx    = MakeTx();
        var rx    = MakeRx();
        byte[] frame = tx.Encrypt([1, 2, 3]);
        frame[^1] ^= 0xFF; // flip last tag byte
        Assert.ThrowsAny<CryptographicException>(() => rx.Decrypt(frame));
    }

    [Fact]
    public void Decrypt_TamperedHeader_ThrowsCryptographicException()
    {
        // The header is used as AAD — flipping it must invalidate the tag.
        var tx    = MakeTx();
        var rx    = MakeRx();
        byte[] frame = tx.Encrypt([1, 2, 3]);
        frame[0] ^= 0xFF; // flip counter byte (also corrupts AAD)
        Assert.ThrowsAny<CryptographicException>(() => rx.Decrypt(frame));
    }

    // ── Replay protection (Spec §7.1) ─────────────────────────────────────────

    [Fact]
    public void Decrypt_ReplayedFrame_ThrowsCryptographicException()
    {
        var tx    = MakeTx();
        var rx    = MakeRx();
        byte[] frame = tx.Encrypt([1]);
        rx.Decrypt(frame);                             // first delivery — OK
        Assert.Throws<CryptographicException>(() => rx.Decrypt(frame)); // replay
    }

    [Fact]
    public void Decrypt_OutOfOrderOlderFrame_ThrowsCryptographicException()
    {
        var tx = MakeTx();
        var rx = MakeRx();
        byte[] frame0 = tx.Encrypt([1]);
        byte[] frame1 = tx.Encrypt([2]);
        rx.Decrypt(frame1);  // deliver frame 1 first
        Assert.Throws<CryptographicException>(() => rx.Decrypt(frame0)); // frame 0 is "older"
    }

    [Fact]
    public void Decrypt_StrictlyIncreasingCounters_AllAccepted()
    {
        var tx = MakeTx();
        var rx = MakeRx();
        for (int i = 0; i < 5; i++)
            rx.Decrypt(tx.Encrypt([(byte)i])); // each counter strictly > previous
    }

    [Fact]
    public void Decrypt_TooShortFrame_ThrowsCryptographicException()
    {
        var rx = MakeRx();
        Assert.Throws<CryptographicException>(() => rx.Decrypt(new byte[10]));
    }

    // ── Construction validation ───────────────────────────────────────────────

    [Fact]
    public void Constructor_WrongKeyLength_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() =>
            new SessionChannel(new byte[16], new byte[12]));
    }

    [Fact]
    public void Constructor_WrongNonceIvLength_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() =>
            new SessionChannel(new byte[32], new byte[8]));
    }

    // ── Handshake-derived session channels agree ──────────────────────────────

    [Fact]
    public void SessionChannel_FromHandshake_EncryptDecryptSucceeds()
    {
        // Wire up a full handshake and use the resulting keys in SessionChannel
        var nodeA = new AetherNode("A");
        var nodeB = new AetherNode("B");

        var hsI = new HandshakeInitiator(
            nodeA.StaticPrivateKey, nodeA.StaticPublicKey,
            nodeA.IdentityPublicKey, nodeA.BindingSig);
        var hsR = new HandshakeResponder(
            nodeB.StaticPrivateKey, nodeB.StaticPublicKey,
            nodeB.IdentityPublicKey, nodeB.BindingSig);

        byte[] msg1 = hsI.Step();
        byte[] msg2 = hsR.Step(msg1);
        byte[] msg3 = hsI.Step(msg2);
        hsR.Step(msg3);

        var txA = new SessionChannel(hsI.SessionKeyToSend!,    hsI.SessionNonceIV!);
        var rxB = new SessionChannel(hsR.SessionKeyToReceive!, hsR.SessionNonceIV!);

        byte[] plaintext = [0xCA, 0xFE, 0xBA, 0xBE];
        byte[] got       = rxB.Decrypt(txA.Encrypt(plaintext));
        Assert.Equal(Convert.ToHexString(plaintext), Convert.ToHexString(got));
    }
}
