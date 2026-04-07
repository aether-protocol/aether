using System.Buffers.Binary;
using PeterO.Cbor;
using System.Collections.Generic;
using System.Linq;

namespace Aether.Core;

/// <summary>
/// Service Layer (Spec Part 3) — handles RPC framing, method dispatch and capability advertising.
/// </summary>
public class ServiceLayer
{
    private readonly CapabilityDescriptor _descriptor;
    private readonly Dictionary<(byte[] ServiceId, byte MethodId), Func<CBORObject, CBORObject>> _handlers = new(ByteArrayComparer.Instance);

    public ServiceLayer(CapabilityDescriptor descriptor)
    {
        _descriptor = descriptor ?? throw new ArgumentNullException(nameof(descriptor));
    }

    public CapabilityDescriptor Descriptor => _descriptor;

    /// <summary>
    /// Register a handler for a specific method.
    /// </summary>
    public void RegisterHandler(byte[] serviceId, byte methodId, Func<CBORObject, CBORObject> handler)
    {
        ArgumentNullException.ThrowIfNull(serviceId);
        _handlers[(serviceId, methodId)] = handler;
    }

    /// <summary>
    /// Process an incoming RPC request frame and return response bytes (or null for fire-and-forget).
    /// </summary>
    public byte[]? ProcessRpcFrame(byte[] frame)
    {
        if (frame.Length < 20)
            throw new InvalidDataException("RPC frame too short");

        byte[] serviceId = frame[0..16];
        byte methodId = frame[16];
        ushort callId = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(17, 2));
        byte flags = frame[19];

        bool isResponseExpected = (flags & 0x01) != 0;
        bool isResponse = (flags & 0x02) != 0;
        bool isEvent = (flags & 0x04) != 0;

        // For now we only handle requests
        if (isResponse || isEvent)
            return null;

        var key = (serviceId, methodId);

        if (!_handlers.TryGetValue(key, out var handler))
        {
            // Return error response: unknown method
            return BuildErrorResponse(callId, 2, "Unknown method");
        }

        // Extract arguments (CBOR map after the 20-byte header)
        CBORObject args = frame.Length > 20
            ? CBORObject.DecodeFromBytes(frame[20..])
            : CBORObject.NewMap();

        try
        {
            CBORObject result = handler(args);

            // Build success response
            return BuildResponse(serviceId, methodId, callId, result);
        }
        catch (Exception ex)
        {
            return BuildErrorResponse(callId, 4, ex.Message);
        }
    }

    private byte[] BuildResponse(byte[] serviceId, byte methodId, ushort callId, CBORObject payload)
    {
        var header = new byte[20];
        serviceId.CopyTo(header, 0);
        header[16] = methodId;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(17), callId);
        header[19] = 0x02; // is response

        if (payload != null && payload.Type != CBORType.SimpleValue)
        {
            byte[] payloadBytes = payload.EncodeToBytes();
            return [.. header, .. payloadBytes];
        }
        return header;
    }

    /// <summary>
    /// Builds an event frame for the given service and event (Spec Part 3 §6).
    /// Event frame layout: service_id(16) ‖ event_id(1) ‖ call_id=0(2 BE) ‖ flags=0x04(1) ‖ CBOR payload
    /// Flags bit 2 = 0x04 marks this as an event (not a request or response).
    /// The caller is responsible for encrypting and transmitting the returned bytes.
    /// </summary>
    /// <param name="serviceId">16-byte service UUID.</param>
    /// <param name="eventId">Event ID within the service.</param>
    /// <param name="payload">CBOR-encoded event payload (e.g. temperature reading map).</param>
    public static byte[] BuildEventFrame(byte[] serviceId, byte eventId, CBORObject payload)
    {
        ArgumentNullException.ThrowIfNull(serviceId);
        if (serviceId.Length != 16) throw new ArgumentException("serviceId must be 16 bytes.", nameof(serviceId));
        ArgumentNullException.ThrowIfNull(payload);

        var header = new byte[20];
        serviceId.CopyTo(header, 0);
        header[16] = eventId;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(17), 0x0000); // call_id unused
        header[19] = 0x04; // flags: is_event

        byte[] payloadBytes = payload.EncodeToBytes();
        return [.. header, .. payloadBytes];
    }

    private byte[] BuildErrorResponse(ushort callId, byte errorCode, string message)
    {
        var errorService = new byte[16]; // all 0xFF = error service
        Array.Fill(errorService, (byte)0xFF);

        var map = CBORObject.NewMap()
            .Add("call_id", callId)
            .Add("err", errorCode)
            .Add("msg", message);

        var header = new byte[20];
        errorService.CopyTo(header, 0);
        header[16] = 0; // not used
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(17), callId);
        header[19] = 0x02; // is response

        byte[] payload = map.EncodeToBytes();
        return [.. header, .. payload];
    }
}

// Simple comparer so we can use byte[] as dictionary key
file class ByteArrayComparer : IEqualityComparer<(byte[] ServiceId, byte MethodId)>
{
    public static readonly ByteArrayComparer Instance = new();

    public bool Equals((byte[] ServiceId, byte MethodId) x, (byte[] ServiceId, byte MethodId) y)
    {
        return x.MethodId == y.MethodId && x.ServiceId.SequenceEqual(y.ServiceId);
    }

    public int GetHashCode((byte[] ServiceId, byte MethodId) obj)
    {
        var hash = new HashCode();
        hash.Add(obj.MethodId);
        foreach (byte b in obj.ServiceId) hash.Add(b);
        return hash.ToHashCode();
    }
}