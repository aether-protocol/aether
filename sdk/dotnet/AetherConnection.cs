using Aether.Core;

namespace Aether.Sdk;

/// <summary>
/// Represents an established Aether connection (handshake complete, keys derived, ready for RPC).
/// </summary>
public class AetherConnection : IAsyncDisposable
{
    private readonly LinkLayer _linkLayer;
    private readonly LinkEndpoint _localEndpoint;

    private SessionChannel? _txChannel;
    private SessionChannel? _rxChannel;

    public AetherNode LocalNode { get; }

    /// <summary>Peer's Ed25519 identity public key, verified during the handshake.</summary>
    public byte[]? PeerIdentityPublicKey { get; private set; }

    /// <summary>Peer's 6-byte device ID: SHA3-256(PeerIdentityPublicKey)[0:6].</summary>
    public byte[]? PeerDeviceId { get; private set; }

    internal AetherConnection(AetherNode local, LinkLayer linkLayer, LinkEndpoint localEndpoint)
    {
        LocalNode      = local;
        _linkLayer     = linkLayer;
        _localEndpoint = localEndpoint;
    }

    // ── Handshake ─────────────────────────────────────────────────────────────

    internal async Task RunAsInitiatorAsync(CancellationToken ct)
    {
        var hs = new HandshakeInitiator(
            LocalNode.StaticPrivateKey, LocalNode.StaticPublicKey,
            LocalNode.IdentityPublicKey, LocalNode.BindingSig);

        // msg1: send
        byte[] msg1 = hs.Step();
        await _localEndpoint.SendAsync(msg1, ct);

        // msg2: receive, process → builds msg3
        byte[] msg2 = await _localEndpoint.ReceiveAsync(ct);
        byte[] msg3 = hs.Step(msg2);

        // msg3: send
        await _localEndpoint.SendAsync(msg3, ct);

        SetSessionState(hs.SessionKeyToSend!, hs.SessionKeyToReceive!,
                        hs.SessionNonceIV!,   hs.PeerIdentityPublicKey!,
                        hs.PeerDeviceId!);
    }

    internal async Task RunAsResponderAsync(CancellationToken ct)
    {
        var hs = new HandshakeResponder(
            LocalNode.StaticPrivateKey, LocalNode.StaticPublicKey,
            LocalNode.IdentityPublicKey, LocalNode.BindingSig);

        // msg1: receive
        byte[] msg1 = await _localEndpoint.ReceiveAsync(ct);

        // msg2: process msg1, send msg2
        byte[] msg2 = hs.Step(msg1);
        await _localEndpoint.SendAsync(msg2, ct);

        // msg3: receive, process
        byte[] msg3 = await _localEndpoint.ReceiveAsync(ct);
        hs.Step(msg3);

        SetSessionState(hs.SessionKeyToSend!, hs.SessionKeyToReceive!,
                        hs.SessionNonceIV!,   hs.PeerIdentityPublicKey!,
                        hs.PeerDeviceId!);
    }

    private void SetSessionState(byte[] txKey, byte[] rxKey, byte[] nonceIv,
                                  byte[] peerIdPub, byte[] peerDeviceId)
    {
        _txChannel           = new SessionChannel(txKey, nonceIv);
        _rxChannel           = new SessionChannel(rxKey, nonceIv);
        PeerIdentityPublicKey = peerIdPub;
        PeerDeviceId          = peerDeviceId;
    }

    // ── Data transfer ─────────────────────────────────────────────────────────

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> and sends it to the peer.
    /// </summary>
    public async ValueTask SendAsync(byte[] plaintext, CancellationToken ct = default)
    {
        EnsureConnected();
        byte[] frame = _txChannel!.Encrypt(plaintext);
        await _localEndpoint.SendAsync(frame, ct);
    }

    /// <summary>
    /// Receives and decrypts the next frame from the peer.
    /// Throws <see cref="System.Security.Cryptography.CryptographicException"/> on
    /// authentication failure or replay.
    /// </summary>
    public async ValueTask<byte[]> ReceiveAsync(CancellationToken ct = default)
    {
        EnsureConnected();
        byte[] frame = await _localEndpoint.ReceiveAsync(ct);
        return _rxChannel!.Decrypt(frame);
    }

    private void EnsureConnected()
    {
        if (_txChannel is null || _rxChannel is null)
            throw new InvalidOperationException("Handshake has not completed.");
    }

    public ValueTask DisposeAsync()
    {
        _linkLayer.Close();
        return ValueTask.CompletedTask;
    }
}
