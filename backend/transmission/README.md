# G Transmission Ether Web v1

A fail-closed transport orchestration layer for −G / GPAY.

## Reality boundary

This subsystem only uses network, radio, satellite, cellular, cloud, VPN, or gateway infrastructure that the operator is authorized to use. Public visibility, discoverability, RF reception, or provider documentation do not constitute authorization to transmit or control infrastructure.

## Adapter contract

Each provider adapter extends `TransportAdapter` and implements:

- `probe()` — authenticated, non-destructive capability verification.
- `send(payload, destination)` — provider-authorized transmission.
- `receive()` — provider-authorized receive path where supported.
- `health()` — local state plus provider telemetry where supported.

A transport cannot send until it has both authorization evidence and a successful verified probe.

## Initial frontier

| Transport | Integration target | Initial state |
| --- | --- | --- |
| Starlink | Management API + Telemetry API for eligible Business/Enterprise/Authorized Reseller accounts | AUTH_REQUIRED |
| LoRaWAN | The Things Stack REST/gRPC/MQTT/Basic Station against owned/authorized gateways and applications | AUTH_REQUIRED |
| Internet/VPS | HTTPS/WebSocket/QUIC relay hosted in an authorized account | AUTH_REQUIRED |
| VPN overlay | WireGuard/Tailscale-style authenticated overlay over authorized endpoints | AUTH_REQUIRED |
| Cellular/IoT | Provider API/SIM management and IP/data transport under an authorized account | AUTH_REQUIRED |

## Starlink boundary

Starlink API access is for eligible accounts and manages accounts, terminals, service lines, configuration and telemetry. It does not grant satellite spacecraft command authority. A Starlink terminal can serve as an Ether Web bearer once account/terminal authorization is proven.

## Routing model

Only `AUTHORIZED_ACTIVE` adapters enter the active routing graph. Candidate routes can be ranked by latency, throughput, loss, cost, trust, availability and authorization freshness. No fallback may silently cross into an unauthorized transport.

## Receipt rule

Every real probe/send operation emits an evidence record containing action, transport, timestamp, destination where applicable, status and provider result/error. Provider request IDs or acknowledgements should be retained by concrete adapters whenever exposed.
