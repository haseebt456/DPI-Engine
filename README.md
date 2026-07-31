# Network Traffic Analyzer (DPI Engine)

A Deep Packet Inspection engine that reads `.pcap` captures, parses raw
Ethernet/IPv4/TCP/UDP headers, classifies traffic by application using
TLS SNI and HTTP Host extraction, and applies configurable blocking rules.

## Why this project exists

Even encrypted HTTPS traffic reveals its destination domain during the TLS
handshake: the ClientHello message includes the **Server Name Indication
(SNI)** in plaintext, before encryption keys are negotiated. This engine
extracts that plaintext domain to classify and optionally block traffic by
application, IP, or domain — the same principle real-world DPI/firewall
systems use.

## Status

- [x] PCAP file parsing (global header + per-packet headers)
- [x] Ethernet / IPv4 / TCP / UDP header parsing
- [x] Five-tuple flow tracking (`unordered_map` keyed on src/dst IP+port+protocol)
- [x] TLS ClientHello SNI extraction
- [x] Plain HTTP Host header extraction
- [x] Rule-based blocking (by app, IP, or domain substring)
- [x] Traffic report (per-app breakdown, forwarded/dropped counts)
- [ ] Multi-threaded pipeline (load balancer + fast-path worker threads)
- [ ] Node.js/Express API + MongoDB storage for historical stats
- [ ] React dashboard for live traffic visualization

## Building

```bash
./build.sh
# or manually:
g++ -std=c++17 -O2 -I include -o dpi_engine \
    src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

## Running

```bash
# Generate a sample capture (requires: pip install scapy)
python3 generate_test_pcap.py

# Run with no rules
./dpi_engine test_traffic.pcap output.pcap

# Run with blocking rules
./dpi_engine test_traffic.pcap output.pcap \
    --block-app YouTube \
    --block-domain facebook \
    --block-ip 192.168.1.50
```

## How it works

1. **`PcapReader`** opens the file, validates the magic number, and yields
   raw packet bytes one at a time.
2. **`PacketParser`** walks the byte layout of each header (Ethernet, IPv4,
   TCP/UDP) to extract MACs, IPs, ports, and the offset where the payload
   begins.
3. Each packet's five-tuple (src IP, dst IP, src port, dst port, protocol)
   is looked up in a flow table. Packets sharing a five-tuple are part of
   the same connection.
4. If the flow hasn't been classified yet and the payload looks large
   enough, **`SNIExtractor`** (for port 443) or **`HTTPHostExtractor`**
   (for port 80) attempts to pull out the destination domain.
5. The domain is mapped to an `AppType`, and **`Rules`** decides whether
   the flow should be blocked — by app, source IP, or domain substring.
6. Once a flow is marked blocked, every subsequent packet in it is dropped
   without re-checking the rules.
7. At the end, a report summarizes packet counts, per-app traffic
   percentages, and which domains/flows were blocked.

## Project structure

```
include/            Header files (declarations)
  types.h            FiveTuple, Flow, AppType
  pcap_reader.h       PCAP file format structs + reader
  packet_parser.h    Ethernet/IPv4/TCP/UDP parsing
  sni_extractor.h    TLS SNI + HTTP Host extraction

src/                 Implementations
  main.cpp           Orchestrates the pipeline, applies rules, reports

generate_test_pcap.py   Builds a sample capture for testing
build.sh                Build script
```

## Roadmap

This is the single-threaded core. Next: a multi-threaded pipeline
(load-balancer + fast-path worker threads with consistent hashing so all
packets of a flow land on the same thread), followed by a Node.js/Express
API and MongoDB store so historical stats persist, and a React dashboard
for live visualization.
