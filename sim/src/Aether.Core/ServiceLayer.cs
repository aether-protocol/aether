namespace Aether.Core;

/// <summary>
/// Service Layer (Spec Part 3) – RPC framing, capability advertising, method dispatch.
/// </summary>
public class ServiceLayer
{
    private readonly CapabilityDescriptor _descriptor;
    private readonly Dictionary<string, object> _handlers = new();

    public ServiceLayer(CapabilityDescriptor descriptor)
    {
        _descriptor = descriptor;
    }

    public CapabilityDescriptor GetDescriptor() => _descriptor;

    public void RegisterService(string serviceId, object handler)
    {
        _handlers[serviceId] = handler;
    }

    // TODO: Add CallMethod, SendEvent, ProcessIncomingRpcFrame, etc.
    // Full RPC framing (service_id + m_id + call_id + flags + CBOR) will be implemented next.
}