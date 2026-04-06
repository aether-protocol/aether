using PeterO.Cbor;
using System.Collections.Generic;
using System.Linq;

namespace Aether.Core;

/// <summary>
/// CBOR-encoded capability descriptor per Spec Part 3 §3.
/// </summary>
public class CapabilityDescriptor
{
    public int Version { get; set; } = 1;

    public DeviceInfo DeviceInfo { get; set; } = new DeviceInfo();

    public List<ServiceDescriptor> Services { get; set; } = new List<ServiceDescriptor>();

    public CryptoCapabilities CryptoCapabilities { get; set; } = new CryptoCapabilities();

    public byte[] ToCborBytes()
    {
        var svArray = CBORObject.NewArray();
        foreach (var service in Services.Select(s => s.ToCbor()))
        {
            svArray.Add(service);
        }

        var map = CBORObject.NewMap()
            .Add("v", Version)
            .Add("di", DeviceInfo.ToCbor())
            .Add("sv", svArray)
            .Add("cc", CryptoCapabilities.ToCbor());

        return map.EncodeToBytes();
    }

    public static CapabilityDescriptor FromCbor(byte[] data)
    {
        // Placeholder for full parsing
        var cbor = CBORObject.DecodeFromBytes(data);
        return new CapabilityDescriptor();
    }
}

public class DeviceInfo
{
    public string Name { get; set; } = "Aether Device";
    public string SoftwareVersion { get; set; } = "0.1.0";
    public string? HardwareVersion { get; set; }
    public string? Manufacturer { get; set; }

    internal CBORObject ToCbor()
    {
        var map = CBORObject.NewMap()
            .Add("n", Name)
            .Add("sv", SoftwareVersion);

        if (HardwareVersion != null) map.Add("hv", HardwareVersion);
        if (Manufacturer != null) map.Add("mn", Manufacturer);

        return map;
    }
}

public class ServiceDescriptor
{
    public byte[] Id { get; set; } = new byte[16];
    public string Version { get; set; } = "1.0.0";
    public List<MethodDescriptor> Methods { get; set; } = new();
    public List<EventDescriptor> Events { get; set; } = new();

    internal CBORObject ToCbor()
    {
        var map = CBORObject.NewMap()
            .Add("id", Id)
            .Add("v", Version);

        if (Methods.Count > 0)
        {
            var mArray = CBORObject.NewArray();
            foreach (var method in Methods.Select(m => m.ToCbor()))
            {
                mArray.Add(method);
            }
            map.Add("m", mArray);
        }

        if (Events.Count > 0)
        {
            var eArray = CBORObject.NewArray();
            foreach (var evt in Events.Select(e => e.ToCbor()))
            {
                eArray.Add(evt);
            }
            map.Add("e", eArray);
        }

        return map;
    }
}

public class MethodDescriptor
{
    public byte MethodId { get; set; }
    public string Name { get; set; } = string.Empty;

    internal CBORObject ToCbor() => CBORObject.NewMap()
        .Add("mid", MethodId)
        .Add("n", Name);
}

public class EventDescriptor
{
    public byte EventId { get; set; }
    public string Name { get; set; } = string.Empty;

    internal CBORObject ToCbor() => CBORObject.NewMap()
        .Add("eid", EventId)
        .Add("n", Name);
}

public class CryptoCapabilities
{
    public bool SupportsChaCha20Poly1305 { get; set; }
    public int MaxMtu { get; set; } = 227;
    public bool SupportsDelayedAck { get; set; }

    internal CBORObject ToCbor()
    {
        var map = CBORObject.NewMap();
        if (SupportsChaCha20Poly1305) map.Add("cc20", true);
        if (MaxMtu != 227) map.Add("mtu", MaxMtu);
        if (SupportsDelayedAck) map.Add("dack", true);
        return map;
    }
}