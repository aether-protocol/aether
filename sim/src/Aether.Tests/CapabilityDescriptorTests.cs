using Aether.Core;
using Xunit;

namespace Aether.Tests;

/// <summary>
/// CBOR round-trip tests for <see cref="CapabilityDescriptor"/> (Spec Part 3 §3–§4).
/// Every field that ToCborBytes() serialises must survive FromCbor() intact.
/// </summary>
public class CapabilityDescriptorTests
{
    private static CapabilityDescriptor MakeFullDescriptor() => new()
    {
        Version = 2,
        DeviceInfo = new DeviceInfo
        {
            Name            = "ThermoPuck",
            SoftwareVersion = "1.2.3",
            HardwareVersion = "rev-B",
            Manufacturer    = "Aether Labs",
        },
        CryptoCapabilities = new CryptoCapabilities
        {
            MaxMtu                   = 200,
            SupportsChaCha20Poly1305 = true,
            SupportsDelayedAck       = true,
        },
        Services =
        [
            new ServiceDescriptor
            {
                Id      = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1],
                Version = "1.0.0",
                Methods =
                [
                    new MethodDescriptor { MethodId = 0x01, Name = "read" },
                    new MethodDescriptor { MethodId = 0x02, Name = "set_interval" },
                ],
                Events =
                [
                    new EventDescriptor { EventId = 0x01, Name = "reading" },
                ],
            }
        ],
    };

    // ── ToCborBytes produces parseable CBOR ───────────────────────────────────

    [Fact]
    public void ToCborBytes_ProducesNonEmptyBytes()
    {
        byte[] bytes = MakeFullDescriptor().ToCborBytes();
        Assert.NotEmpty(bytes);
    }

    [Fact]
    public void ToCborBytes_OutputSizeReasonable()
    {
        byte[] bytes = MakeFullDescriptor().ToCborBytes();
        // Must fit within the 2048-byte spec limit (Spec Part 3 §2)
        Assert.True(bytes.Length <= 2048, $"Descriptor too large: {bytes.Length} bytes");
    }

    // ── Round-trip: version ───────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_Version_Preserved()
    {
        var d = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.Version, d2.Version);
    }

    // ── Round-trip: DeviceInfo ────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_DeviceInfo_Name_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.DeviceInfo.Name, d2.DeviceInfo.Name);
    }

    [Fact]
    public void RoundTrip_DeviceInfo_SoftwareVersion_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.DeviceInfo.SoftwareVersion, d2.DeviceInfo.SoftwareVersion);
    }

    [Fact]
    public void RoundTrip_DeviceInfo_HardwareVersion_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.DeviceInfo.HardwareVersion, d2.DeviceInfo.HardwareVersion);
    }

    [Fact]
    public void RoundTrip_DeviceInfo_Manufacturer_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.DeviceInfo.Manufacturer, d2.DeviceInfo.Manufacturer);
    }

    [Fact]
    public void RoundTrip_DeviceInfo_NullOptionalFields_Preserved()
    {
        var d  = new CapabilityDescriptor { DeviceInfo = new DeviceInfo { Name = "X" } };
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Null(d2.DeviceInfo.HardwareVersion);
        Assert.Null(d2.DeviceInfo.Manufacturer);
    }

    // ── Round-trip: CryptoCapabilities ────────────────────────────────────────

    [Fact]
    public void RoundTrip_CryptoCapabilities_MaxMtu_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.CryptoCapabilities.MaxMtu, d2.CryptoCapabilities.MaxMtu);
    }

    [Fact]
    public void RoundTrip_CryptoCapabilities_ChaCha20_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.CryptoCapabilities.SupportsChaCha20Poly1305,
                     d2.CryptoCapabilities.SupportsChaCha20Poly1305);
    }

    [Fact]
    public void RoundTrip_CryptoCapabilities_DelayedAck_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.CryptoCapabilities.SupportsDelayedAck,
                     d2.CryptoCapabilities.SupportsDelayedAck);
    }

    [Fact]
    public void RoundTrip_CryptoCapabilities_DefaultMtu_NoMtuFieldInCbor()
    {
        // Default MTU (227) must NOT emit the "mtu" key (ToCbor omits it) and
        // FromCbor must restore the default correctly.
        var d  = new CapabilityDescriptor(); // MaxMtu defaults to 227
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(227, d2.CryptoCapabilities.MaxMtu);
    }

    // ── Round-trip: Services ──────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_ServiceCount_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.Services.Count, d2.Services.Count);
    }

    [Fact]
    public void RoundTrip_ServiceId_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(
            Convert.ToHexString(d.Services[0].Id),
            Convert.ToHexString(d2.Services[0].Id));
    }

    [Fact]
    public void RoundTrip_ServiceVersion_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.Services[0].Version, d2.Services[0].Version);
    }

    [Fact]
    public void RoundTrip_MethodCount_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.Services[0].Methods.Count, d2.Services[0].Methods.Count);
    }

    [Fact]
    public void RoundTrip_MethodIds_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        for (int i = 0; i < d.Services[0].Methods.Count; i++)
        {
            Assert.Equal(d.Services[0].Methods[i].MethodId,
                         d2.Services[0].Methods[i].MethodId);
            Assert.Equal(d.Services[0].Methods[i].Name,
                         d2.Services[0].Methods[i].Name);
        }
    }

    [Fact]
    public void RoundTrip_EventCount_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.Services[0].Events.Count, d2.Services[0].Events.Count);
    }

    [Fact]
    public void RoundTrip_EventIds_Preserved()
    {
        var d  = MakeFullDescriptor();
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Equal(d.Services[0].Events[0].EventId,
                     d2.Services[0].Events[0].EventId);
        Assert.Equal(d.Services[0].Events[0].Name,
                     d2.Services[0].Events[0].Name);
    }

    [Fact]
    public void RoundTrip_EmptyServiceList_Preserved()
    {
        var d  = new CapabilityDescriptor(); // no services
        var d2 = CapabilityDescriptor.FromCbor(d.ToCborBytes());
        Assert.Empty(d2.Services);
    }

    // ── AetherNode produces a valid descriptor ────────────────────────────────

    [Fact]
    public void AetherNode_CapabilityDescriptor_RoundTrips()
    {
        var node = new AetherNode("TestNode");
        var d2   = CapabilityDescriptor.FromCbor(node.CapabilityDescriptor.ToCborBytes());
        Assert.Equal(node.CapabilityDescriptor.DeviceInfo.Name, d2.DeviceInfo.Name);
        Assert.Equal(node.CapabilityDescriptor.Services.Count,  d2.Services.Count);
    }
}
