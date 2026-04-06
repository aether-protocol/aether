namespace Aether.Core;

/// <summary>
/// A simulated Aether device. Owns an Ed25519 identity keypair, a device address
/// (SHA3-256 of the public key, truncated to 6 bytes), and the full protocol stack:
/// LinkLayer → Handshake → ServiceLayer.
/// </summary>
/// <remarks>
/// The spec (§1) uses Ed25519 for identity/device-ID and X25519 for Noise DH.
/// In a full implementation the two keypairs are bound by signing the X25519 static
/// public key with the Ed25519 identity key. The simulator carries both but keeps
/// the binding implicit: the Noise handshake advertises and verifies the X25519 key,
/// and the device ID is derived from the Ed25519 key.
/// </remarks>
public class AetherNode
{
    public string Name { get; }

    // Ed25519 long-term identity (Spec §4): used for device ID and signing.
    public byte[] IdentityPrivateKey { get; }
    public byte[] IdentityPublicKey  { get; }

    // X25519 static keypair: used as the Noise XX static key in DH operations.
    // In the Noise handshake the peer's X25519 static public key is what is
    // encrypted and transmitted; the Ed25519 key is the application-layer identity.
    public byte[] StaticPrivateKey { get; }
    public byte[] StaticPublicKey  { get; }

    /// <summary>6-byte device address: SHA3-256(Ed25519 pubkey)[0:6] (Spec §4.2).</summary>
    public byte[] DeviceId { get; }

    /// <summary>
    /// Ed25519 signature over the X25519 static public key (Spec §4.1.1).
    /// Proves to peers that StaticPublicKey belongs to this identity.
    /// </summary>
    public byte[] BindingSig { get; }

    public AetherNode(string name)
    {
        Name = name;
        (IdentityPrivateKey, IdentityPublicKey) = Crypto.GenerateIdentityKeypair();
        DeviceId = Crypto.DeriveDeviceId(IdentityPublicKey);
        (StaticPrivateKey, StaticPublicKey) = Crypto.GenerateEphemeralKeypair();
        BindingSig = Crypto.Ed25519Sign(IdentityPrivateKey, StaticPublicKey);
    }
}
