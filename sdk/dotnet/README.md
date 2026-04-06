# Aether .NET SDK

Official C# SDK for building applications on top of the Aether protocol.

**Current status**: Early alpha – wraps the simulator (`Aether.Core`). Host-stack support coming soon.

## Quick start

```csharp
using Aether.Sdk;

var client = new AetherClient("MyPhone");
var conn = await client.ConnectToSimulatorAsync();
Console.WriteLine("Connected securely to Aether device!");