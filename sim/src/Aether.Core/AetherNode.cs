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
    
    /// <summary>
    /// Capability descriptor advertised during discovery (Spec Part 3).
    /// </summary>
    public CapabilityDescriptor CapabilityDescriptor { get; }

    public AetherNode(string name)
    {
        Name = name;

        // Generate keys (existing logic)
        (IdentityPrivateKey, IdentityPublicKey) = Crypto.GenerateIdentityKeypair();
        DeviceId = Crypto.DeriveDeviceId(IdentityPublicKey);
        (StaticPrivateKey, StaticPublicKey) = Crypto.GenerateEphemeralKeypair();
        BindingSig = Crypto.Ed25519Sign(IdentityPrivateKey, StaticPublicKey);

        // Create a basic capability descriptor (Part 3)
        CapabilityDescriptor = new CapabilityDescriptor
        {
            DeviceInfo = new DeviceInfo
            {
                Name = name,
                SoftwareVersion = "0.1.0",
                Manufacturer = "Aether Protocol Contributors"
            },
            CryptoCapabilities = new CryptoCapabilities
            {
                MaxMtu = 227,
                SupportsChaCha20Poly1305 = false,
                SupportsDelayedAck = true
            }
        };

        // Add the standard Temperature service as an example (Spec Part 3 §7)
        var tempService = new ServiceDescriptor
        {
            Id = new byte[16] { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 }, // Temperature UUID
            Version = "1.0.0"
        };

        tempService.Methods.Add(new MethodDescriptor
        {
            MethodId = 0x01,
            Name = "read"
        });

        tempService.Events.Add(new EventDescriptor
        {
            EventId = 0x01,
            Name = "reading"
        });

        CapabilityDescriptor.Services.Add(tempService);
    }
}
