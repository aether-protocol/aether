using System.Threading.Channels;

namespace Aether.Core;

/// <summary>
/// In-process link-layer transport between two <see cref="LinkEndpoint"/> instances.
/// Models a bidirectional Aether link without serialisation: raw byte arrays are
/// passed through two <see cref="Channel{T}"/> queues, one per direction.
/// </summary>
/// <remarks>
/// Create a <see cref="LinkLayer"/> to get a connected pair of endpoints:
/// <code>
///   var link = new LinkLayer();
///   LinkEndpoint a = link.EndpointA;
///   LinkEndpoint b = link.EndpointB;
///
///   await a.SendAsync(frame);
///   byte[] frame = await b.ReceiveAsync();
/// </code>
/// </remarks>
public sealed class LinkLayer
{
    // A→B: written by A, read by B.
    private readonly Channel<byte[]> _aToB;
    // B→A: written by B, read by A.
    private readonly Channel<byte[]> _bToA;

    public LinkLayer()
    {
        // Unbounded so that a fast sender is never blocked by the channel itself;
        // back-pressure is the caller's responsibility (matches real radio behaviour
        // where the TX queue can fill up independently of the receiver).
        var opts = new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false,
        };
        _aToB = Channel.CreateUnbounded<byte[]>(opts);
        _bToA = Channel.CreateUnbounded<byte[]>(opts);

        EndpointA = new LinkEndpoint(_aToB.Writer, _bToA.Reader);
        EndpointB = new LinkEndpoint(_bToA.Writer, _aToB.Reader);
    }

    /// <summary>First endpoint of the link (sends on A→B, receives on B→A).</summary>
    public LinkEndpoint EndpointA { get; }

    /// <summary>Second endpoint of the link (sends on B→A, receives on A→B).</summary>
    public LinkEndpoint EndpointB { get; }

    /// <summary>
    /// Signals that no more frames will be written to either direction.
    /// Any pending <see cref="LinkEndpoint.ReceiveAsync"/> calls will complete
    /// with <see cref="ChannelClosedException"/>.
    /// </summary>
    public void Close()
    {
        _aToB.Writer.TryComplete();
        _bToA.Writer.TryComplete();
    }
}

/// <summary>
/// One end of a <see cref="LinkLayer"/> link.
/// Exposes <see cref="SendAsync"/> and <see cref="ReceiveAsync"/> over the
/// underlying channel pair.
/// </summary>
public sealed class LinkEndpoint
{
    private readonly ChannelWriter<byte[]> _tx;
    private readonly ChannelReader<byte[]> _rx;

    internal LinkEndpoint(ChannelWriter<byte[]> tx, ChannelReader<byte[]> rx)
    {
        _tx = tx;
        _rx = rx;
    }

    /// <summary>
    /// Enqueues <paramref name="frame"/> for delivery to the remote endpoint.
    /// The byte array is not copied; callers must not mutate it after this call.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the send.</param>
    public ValueTask SendAsync(byte[] frame, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(frame);
        return _tx.WriteAsync(frame, cancellationToken);
    }

    /// <summary>
    /// Waits for and returns the next frame delivered by the remote endpoint.
    /// </summary>
    /// <param name="cancellationToken">Token to cancel the wait.</param>
    /// <exception cref="ChannelClosedException">
    /// Thrown when the link has been closed and no more frames will arrive.
    /// </exception>
    public ValueTask<byte[]> ReceiveAsync(CancellationToken cancellationToken = default) =>
        _rx.ReadAsync(cancellationToken);

    /// <summary>
    /// Returns <c>true</c> if at least one frame is immediately available without waiting.
    /// </summary>
    public bool TryReceive(out byte[] frame) => _rx.TryRead(out frame!);
}
