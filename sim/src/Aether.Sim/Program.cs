using System.Buffers.Binary;
using Aether.Core;
using Aether.Sdk;
using PeterO.Cbor;

// ── Helpers ───────────────────────────────────────────────────────────────────

static string Hex(ReadOnlySpan<byte> data, int wrap = 16)
{
    var sb = new System.Text.StringBuilder();
    for (int i = 0; i < data.Length; i++)
    {
        if (i > 0 && i % wrap == 0) sb.Append("\n              ");
        else if (i > 0) sb.Append(' ');
        sb.Append(data[i].ToString("X2"));
    }
    return sb.ToString();
}

static void Print(string tag, ReadOnlySpan<byte> frame)
{
    Console.WriteLine($"  {tag,-36} ({frame.Length,4} B)  {Hex(frame)}");
}

{
// ─────────────────────────────────────────────────────────────────────────────
// Demo
// ─────────────────────────────────────────────────────────────────────────────

    Console.WriteLine("═══════════════════════════════════════════════════════════");
    Console.WriteLine("  AETHER PROTOCOL SIMULATOR — End-to-End Demo");
    Console.WriteLine("═══════════════════════════════════════════════════════════");
    Console.WriteLine();

// ── 1. Create nodes ───────────────────────────────────────────────────────────

    var nodeA = new AetherNode("Node-A");
    var nodeB = new AetherNode("Node-B");

    Console.WriteLine("── 1. Device Identities ────────────────────────────────────");
    foreach (var (node, label) in new[] { (nodeA, "A"), (nodeB, "B") })
    {
        Console.WriteLine($"  Node-{label}  id={Hex(node.DeviceId)}  " +
                          $"name=\"{node.CapabilityDescriptor.DeviceInfo.Name}\"");
    }
    Console.WriteLine();

// ── 2. Discovery: ADV + SCAN_REQ/RSP ─────────────────────────────────────────

    Console.WriteLine("── 2. Discovery (ADV → SCAN_REQ → SCAN_RSP) ───────────────");

    var discoveryLink = new LinkLayer();

    // Node B advertises
    byte[] adv = DiscoveryLayer.BuildAdv(
        nodeB.DeviceId,
        advFlags: 0x01,         // connectable
        capabilityDescriptor: nodeB.CapabilityDescriptor,
        name: nodeB.CapabilityDescriptor.DeviceInfo.Name);

    await discoveryLink.EndpointB.SendAsync(adv);
    byte[] advRecv = await discoveryLink.EndpointA.ReceiveAsync();
    var advInfo = DiscoveryLayer.ParseAdv(advRecv)!;
    Print("ADV  B→A", advRecv);
    Console.WriteLine($"    connectable={advInfo.IsConnectable}  " +
                      $"cap_hash={Hex(advInfo.CapHash)}  name=\"{advInfo.Name}\"");
    Console.WriteLine();

    // Node A requests full descriptor (cap_hash mismatch simulated by always requesting)
    byte[] scanReq = DiscoveryLayer.BuildScanReq(nodeA.DeviceId, advInfo.DeviceId);
    await discoveryLink.EndpointA.SendAsync(scanReq);
    byte[] scanReqRecv = await discoveryLink.EndpointB.ReceiveAsync();
    Print("SCAN_REQ  A→B", scanReqRecv);

    // Node B replies with its full capability descriptor
    byte[] scanRsp = DiscoveryLayer.BuildScanRsp(nodeB.CapabilityDescriptor);
    await discoveryLink.EndpointB.SendAsync(scanRsp);
    byte[] scanRspRecv = await discoveryLink.EndpointA.ReceiveAsync();
    Print("SCAN_RSP  B→A", scanRspRecv);

    var peerDesc = DiscoveryLayer.ParseScanRsp(scanRspRecv)!;
    Console.WriteLine($"    parsed descriptor: \"{peerDesc.DeviceInfo.Name}\"  " +
                      $"v{peerDesc.Version}  " +
                      $"{peerDesc.Services.Count} service(s)");
    Console.WriteLine();

    discoveryLink.Close();

// ── 3. Connection: Noise XX handshake via AetherClient ────────────────────────

    Console.WriteLine("── 3. Noise XX Handshake (via AetherClient) ────────────────");

    var (connA, connB) = await AetherClient.CreateSimulatedPairAsync("Node-A", "Node-B");

    Console.WriteLine($"  [OK] Handshake complete.");
    Console.WriteLine($"    A sees peer: {Hex(connA.PeerDeviceId!)}");
    Console.WriteLine($"    B sees peer: {Hex(connB.PeerDeviceId!)}");
    Console.WriteLine($"    Peer IDs match: {connA.PeerDeviceId!.SequenceEqual(connB.LocalNode.DeviceId) && connB.PeerDeviceId!.SequenceEqual(connA.LocalNode.DeviceId)}");
    Console.WriteLine();

// ── 4. RPC: Temperature.read (request/response) ───────────────────────────────

    Console.WriteLine("── 4. RPC: Temperature.read ────────────────────────────────");

    // Register Temperature service on B's connection
    byte[] tempServiceId = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1];
    const ushort CallId  = 0x002A;
    const byte   FlagReq = 0x01;   // response expected

    var serviceB = new ServiceLayer(connB.LocalNode.CapabilityDescriptor);
    serviceB.RegisterHandler(tempServiceId, TemperatureSensor.MethodRead, _ =>
        CBORObject.NewMap()
            .Add("t",    21500)
            .Add("unit", 0));

    // A builds and sends RPC request frame, encrypted through SessionChannel
    byte[] rpcReqBody = new byte[20];
    tempServiceId.CopyTo(rpcReqBody, 0);
    rpcReqBody[16] = TemperatureSensor.MethodRead;
    BinaryPrimitives.WriteUInt16BigEndian(rpcReqBody.AsSpan(17), CallId);
    rpcReqBody[19] = FlagReq;

    await connA.SendAsync(rpcReqBody);
    Console.WriteLine("  [A→B] Temperature.read request (encrypted)");

    // B decrypts, dispatches, encrypts response
    byte[] reqDecrypted = await connB.ReceiveAsync();
    byte[] responseBody = serviceB.ProcessRpcFrame(reqDecrypted)!;
    await connB.SendAsync(responseBody);
    Console.WriteLine("  [B→A] Temperature response (encrypted)");

    // A decrypts and parses the response
    byte[] rspDecrypted = await connA.ReceiveAsync();
    var rspCbor  = CBORObject.DecodeFromBytes(rspDecrypted[20..]);
    int  tempC   = rspCbor["t"].AsInt32();
    string unit  = rspCbor["unit"].AsInt32() == 0 ? "°C" : "?";
    Console.WriteLine($"  RESULT: {tempC / 1000.0:F3} {unit}  ({tempC} m°C)");
    Console.WriteLine();

// ── 5. Events: TemperatureSensor emits readings ───────────────────────────────

    Console.WriteLine("── 5. Events: TemperatureSensor.reading ────────────────────");

    // Simulate a varying temperature: each reading increments by 10 m°C
    int currentTemp = 21500;
    using var cts = new CancellationTokenSource();

    // Attach a TemperatureSensor to connB (it will send events to connA)
    await using var sensor = new TemperatureSensor(connB, intervalMs: 80);
    sensor.ReadTemperature = () => Interlocked.Add(ref currentTemp, 10);
    sensor.Start(cts.Token);

    // A receives 5 events
    for (int i = 0; i < 5; i++)
    {
        byte[] eventFrame  = await connA.ReceiveAsync();
        // events: service_id(16) | event_id(1) | call_id(2) | flags=0x04(1) | CBOR
        var    eventCbor   = CBORObject.DecodeFromBytes(eventFrame[20..]);
        int    t           = eventCbor["t"].AsInt32();
        long   ts          = eventCbor["ts"].ToObject<long>();
        Console.WriteLine($"  [event #{i + 1}]  t={t / 1000.0:F3} °C  ts={ts}");
    }

    await cts.CancelAsync();
    await sensor.StopAsync();

    Console.WriteLine();
    Console.WriteLine("  Stack verified: Discovery → Noise XX → SessionChannel → RPC → Events.");
}
