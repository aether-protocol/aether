using Aether.Core;

namespace Aether.Sdk;

/// <summary>
/// High-level entry point for Aether applications.
/// </summary>
public class AetherClient : IAsyncDisposable
{
    public AetherNode LocalNode { get; }

    public AetherClient(string name = "Aether App")
    {
        LocalNode = new AetherNode(name);
    }

    /// <summary>
    /// Creates an in-process connection pair and runs the full Noise XX handshake,
    /// returning both connected endpoints. Useful for integration tests and simulation.
    /// </summary>
    public static async Task<(AetherConnection Initiator, AetherConnection Responder)>
        CreateSimulatedPairAsync(
            string initiatorName = "Node-I",
            string responderName = "Node-R",
            CancellationToken ct = default)
    {
        var nodeI = new AetherNode(initiatorName);
        var nodeR = new AetherNode(responderName);
        var link  = new LinkLayer();

        var connI = new AetherConnection(nodeI, link, link.EndpointA);
        var connR = new AetherConnection(nodeR, link, link.EndpointB);

        await Task.WhenAll(
            connI.RunAsInitiatorAsync(ct),
            connR.RunAsResponderAsync(ct));

        return (connI, connR);
    }

    /// <summary>
    /// For early development: creates a simulated initiator-side connection.
    /// The peer must be running <see cref="AetherConnection.RunAsResponderAsync"/> on EndpointB
    /// of the same <see cref="LinkLayer"/>.
    /// </summary>
    public async Task<AetherConnection> ConnectToSimulatorAsync(
        LinkLayer link,
        CancellationToken ct = default)
    {
        var conn = new AetherConnection(LocalNode, link, link.EndpointA);
        await conn.RunAsInitiatorAsync(ct);
        return conn;
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }
}
