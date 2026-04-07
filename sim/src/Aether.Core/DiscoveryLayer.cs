using System.Buffers.Binary;

namespace Aether.Core;

/// <summary>
/// Builds and parses Aether link-layer discovery frames (Spec Part 2 §4).
///
/// Frame header (4 bytes):
///   byte 0: (Ver=0x1 &lt;&lt; 4) | Type  — upper nibble = protocol version, lower = frame type
///   byte 1: Flags                    — type-specific flags
///   bytes 2-3: Length (BE)           — total frame length including the 4-byte header
///
/// Frame types used here:
///   0x0 ADV      — advertisement beacon (broadcast)
///   0x1 SCAN_REQ — request full capability descriptor (unicast)
///   0x2 SCAN_RSP — full capability descriptor response (unicast)
/// </summary>
public static class DiscoveryLayer
{
    // ── Frame type constants ─────────────────────────────────────────────────────
    public const byte TypeAdv     = 0x0;
    public const byte TypeScanReq = 0x1;
    public const byte TypeScanRsp = 0x2;

    private const byte Ver = 0x1;

    // ── ADV ───────────────────────────────────────────────────────────────────────
    //
    // Body layout:
    //   src_addr  (6B) — device ID (SHA3-256(idPub)[0:6])
    //   adv_flags (1B) — bit 0: connectable, bit 1: privacy, bit 2: low-power, bit 3: infrastructure
    //   cap_hash  (4B) — SHA3-256(CBOR descriptor)[0:4]
    //   name_len  (1B)
    //   name      (variable, UTF-8, ≤60B)

    /// <summary>
    /// Builds an ADV broadcast frame.
    /// </summary>
    /// <param name="deviceId">6-byte device ID.</param>
    /// <param name="advFlags">
    /// Bit 0 = connectable, bit 1 = privacy mode, bit 2 = low-power, bit 3 = infrastructure.
    /// </param>
    /// <param name="capabilityDescriptor">Descriptor to hash for the cap_hash field.</param>
    /// <param name="name">Optional human-readable device name (truncated to 60 bytes).</param>
    public static byte[] BuildAdv(
        byte[] deviceId,
        byte advFlags,
        CapabilityDescriptor capabilityDescriptor,
        string? name = null)
    {
        ArgumentNullException.ThrowIfNull(deviceId);
        if (deviceId.Length != 6) throw new ArgumentException("deviceId must be 6 bytes.", nameof(deviceId));
        ArgumentNullException.ThrowIfNull(capabilityDescriptor);

        byte[] capHash = ComputeCapHash(capabilityDescriptor);
        byte[] nameBytes = name is null ? [] : System.Text.Encoding.UTF8.GetBytes(name);
        if (nameBytes.Length > 60) nameBytes = nameBytes[..60];

        // body: src_addr(6) + adv_flags(1) + cap_hash(4) + name_len(1) + name
        byte[] body = [.. deviceId, advFlags, .. capHash, (byte)nameBytes.Length, .. nameBytes];
        return BuildFrame(TypeAdv, 0x00, body);
    }

    /// <summary>Parses an ADV frame. Returns null if the frame is not a valid ADV.</summary>
    public static AdvInfo? ParseAdv(byte[] frame)
    {
        if (!TryParseHeader(frame, out var type, out _, out _) || type != TypeAdv) return null;
        ReadOnlySpan<byte> body = frame.AsSpan(4);
        if (body.Length < 12) return null;   // 6 + 1 + 4 + 1 minimum

        byte[] deviceId  = body[..6].ToArray();
        byte   advFlags  = body[6];
        byte[] capHash   = body[7..11].ToArray();
        int    nameLen   = body[11];
        string name      = nameLen > 0 && body.Length >= 12 + nameLen
            ? System.Text.Encoding.UTF8.GetString(body.Slice(12, nameLen))
            : string.Empty;

        return new AdvInfo(deviceId, advFlags, capHash, name);
    }

    // ── SCAN_REQ ─────────────────────────────────────────────────────────────────
    //
    // Body: src_addr(6) + dst_addr(6)

    /// <summary>Builds a SCAN_REQ unicast frame.</summary>
    public static byte[] BuildScanReq(byte[] srcDeviceId, byte[] dstDeviceId)
    {
        ArgumentNullException.ThrowIfNull(srcDeviceId);
        ArgumentNullException.ThrowIfNull(dstDeviceId);
        if (srcDeviceId.Length != 6) throw new ArgumentException("srcDeviceId must be 6 bytes.", nameof(srcDeviceId));
        if (dstDeviceId.Length != 6) throw new ArgumentException("dstDeviceId must be 6 bytes.", nameof(dstDeviceId));

        return BuildFrame(TypeScanReq, 0x00, [.. srcDeviceId, .. dstDeviceId]);
    }

    /// <summary>Parses a SCAN_REQ frame.</summary>
    public static ScanReqInfo? ParseScanReq(byte[] frame)
    {
        if (!TryParseHeader(frame, out var type, out _, out _) || type != TypeScanReq) return null;
        ReadOnlySpan<byte> body = frame.AsSpan(4);
        if (body.Length < 12) return null;

        return new ScanReqInfo(body[..6].ToArray(), body[6..12].ToArray());
    }

    // ── SCAN_RSP ─────────────────────────────────────────────────────────────────
    //
    // Body: full CBOR-encoded capability descriptor (≤2048 bytes per spec)

    /// <summary>Builds a SCAN_RSP frame containing the full CBOR capability descriptor.</summary>
    public static byte[] BuildScanRsp(CapabilityDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        byte[] cbor = descriptor.ToCborBytes();
        if (cbor.Length > 2048)
            throw new InvalidOperationException(
                $"Capability descriptor is {cbor.Length} bytes; maximum is 2048 (Spec §4.2).");
        return BuildFrame(TypeScanRsp, 0x00, cbor);
    }

    /// <summary>Parses a SCAN_RSP frame and deserializes the capability descriptor.</summary>
    public static CapabilityDescriptor? ParseScanRsp(byte[] frame)
    {
        if (!TryParseHeader(frame, out var type, out _, out int length) || type != TypeScanRsp) return null;
        if (frame.Length < length) return null;

        byte[] cbor = frame[4..length];
        return CapabilityDescriptor.FromCbor(cbor);
    }

    // ── Shared helpers ────────────────────────────────────────────────────────────

    /// <summary>Returns true if the frame is an ADV from <paramref name="deviceId"/>.</summary>
    public static bool IsAdvFrom(byte[] frame, byte[] deviceId)
    {
        var info = ParseAdv(frame);
        return info is not null && info.DeviceId.SequenceEqual(deviceId);
    }

    /// <summary>Computes the 4-byte cap_hash: SHA3-256(CBOR descriptor)[0:4].</summary>
    public static byte[] ComputeCapHash(CapabilityDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        return Crypto.Sha3Hash256(descriptor.ToCborBytes())[..4];
    }

    // ── Frame building / parsing ──────────────────────────────────────────────────

    private static byte[] BuildFrame(byte type, byte flags, byte[] body)
    {
        int totalLength = 4 + body.Length;
        byte[] frame = new byte[totalLength];
        frame[0] = (byte)((Ver << 4) | (type & 0x0F));
        frame[1] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2), (ushort)totalLength);
        body.CopyTo(frame, 4);
        return frame;
    }

    private static bool TryParseHeader(byte[] frame, out byte type, out byte flags, out int length)
    {
        type = 0; flags = 0; length = 0;
        if (frame is null || frame.Length < 4) return false;
        type   = (byte)(frame[0] & 0x0F);
        flags  = frame[1];
        length = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(2));
        return frame.Length >= length;
    }
}

// ── Parsed frame models ────────────────────────────────────────────────────────

public sealed record AdvInfo(
    byte[] DeviceId,
    byte   AdvFlags,
    byte[] CapHash,
    string Name)
{
    public bool IsConnectable => (AdvFlags & 0x01) != 0;
}

public sealed record ScanReqInfo(byte[] SrcDeviceId, byte[] DstDeviceId);
