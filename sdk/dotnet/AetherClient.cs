using Aether.Core;

namespace Aether.Sdk;

/// <summary>
/// High-level entry point for Aether applications.
/// Wraps the core protocol (simulator mode today).
/// </summary>
public class AetherClient : IAsyncDisposable
{
    public AetherNode LocalNode { get; }

    public AetherClient(string name = "Aether App")
    {
        LocalNode = new AetherNode(name);
    }

    /// <summary>
    /// For early development: creates a simulated connection (full handshake + service layer coming soon).
    /// </summary>
    public async Task<AetherConnection> ConnectToSimulatorAsync(string remoteNodeName = "Node-B", CancellationToken ct = default)
    {
        var connection = new AetherConnection(LocalNode, remoteNodeName);
        await connection.PerformHandshakeAsync(ct);
        return connection;
    }

    public ValueTask DisposeAsync()
    {
        // Cleanup will be added when we have active connections
        return ValueTask.CompletedTask;
    }
}