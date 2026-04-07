using Aether.Core;
using PeterO.Cbor;

namespace Aether.Sdk;

/// <summary>
/// Example sensor class that registers a Temperature service on a connection and
/// periodically emits <c>reading</c> events (Spec Part 3 §7).
///
/// Usage:
/// <code>
///   var sensor = new TemperatureSensor(connection, intervalMs: 500);
///   sensor.Start(ct);          // begins emitting events
///   await sensor.StopAsync();  // sends a final event and cancels the loop
/// </code>
///
/// The sensor also handles inbound <c>Temperature.read</c> RPC calls by calling
/// <see cref="ReadTemperature"/> and returning the current value.
/// </summary>
public sealed class TemperatureSensor : IAsyncDisposable
{
    // Temperature service UUID: 00000000-0000-0000-0000-000000000001
    public static readonly byte[] ServiceId =
        [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1];

    public const byte MethodRead        = 0x01;
    public const byte MethodSetInterval = 0x02;
    public const byte EventReading      = 0x01;

    private readonly AetherConnection _connection;
    private readonly ServiceLayer _service;
    private int _intervalMs;
    private Task _emitLoop = Task.CompletedTask;
    private CancellationTokenSource? _cts;

    /// <summary>
    /// Called to obtain the current temperature in millidegrees Celsius.
    /// Defaults to a constant 21500 (21.5°C). Replace with real hardware reads.
    /// </summary>
    public Func<int> ReadTemperature { get; set; } = () => 21500;

    public TemperatureSensor(AetherConnection connection, int intervalMs = 1000)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (intervalMs < 0) throw new ArgumentOutOfRangeException(nameof(intervalMs));

        _connection = connection;
        _intervalMs = intervalMs;

        _service = new ServiceLayer(connection.LocalNode.CapabilityDescriptor);

        // Handle Temperature.read — returns the current reading
        _service.RegisterHandler(ServiceId, MethodRead, _ =>
            CBORObject.NewMap()
                .Add("t",    ReadTemperature())
                .Add("unit", 0));  // 0 = Celsius

        // Handle Temperature.set_interval — caller can change the event rate
        _service.RegisterHandler(ServiceId, MethodSetInterval, args =>
        {
            if (args.ContainsKey("ms"))
                _intervalMs = args["ms"].AsInt32();
            return CBORObject.Null;
        });
    }

    /// <summary>The service layer, for processing inbound RPC frames.</summary>
    public ServiceLayer ServiceLayer => _service;

    /// <summary>Current event emission interval in milliseconds. 0 = disabled.</summary>
    public int IntervalMs => _intervalMs;

    /// <summary>
    /// Starts the background event emission loop.
    /// Calling <see cref="Start"/> while already running replaces the previous loop.
    /// </summary>
    public void Start(CancellationToken externalCt = default)
    {
        _cts?.Cancel();
        _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        _emitLoop = EmitLoopAsync(_cts.Token);
    }

    /// <summary>Stops the emission loop and awaits its completion.</summary>
    public async Task StopAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync();
            try { await _emitLoop; }
            catch (OperationCanceledException) { /* expected */ }
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync();

    // ── Internals ─────────────────────────────────────────────────────────────────

    private async Task EmitLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            int ms = _intervalMs;
            if (ms <= 0)
            {
                // Events disabled — wait briefly then re-check
                await Task.Delay(100, ct);
                continue;
            }

            await Task.Delay(ms, ct);
            ct.ThrowIfCancellationRequested();

            byte[] eventFrame = ServiceLayer.BuildEventFrame(
                ServiceId,
                EventReading,
                CBORObject.NewMap()
                    .Add("t",    ReadTemperature())
                    .Add("unit", 0)
                    .Add("ts",   DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));

            await _connection.SendAsync(eventFrame, ct);
        }
    }
}
