# Network Traffic Analyzer (DPI Engine)

A Deep Packet Inspection engine that classifies and blocks network traffic
by application, using TLS SNI and HTTP Host extraction — without decrypting
any traffic. Includes an offline `.pcap` analysis engine (single- and
multi-threaded) and a live traffic-blocking agent for Windows.

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
- [x] Multi-threaded pipeline (dispatcher + worker pool, consistent hashing
      on the five-tuple so each connection is always handled by the same
      thread — verified race-free with ThreadSanitizer)
- [x] Live traffic interception on Windows via WinDivert (see `windivert_agent/`)
- [x] CMake build covering all targets (Linux + Windows)
- [ ] Node.js/Express API + MongoDB storage for historical stats
- [ ] React dashboard for live traffic visualization
- [ ] Windows Service packaging + multi-device fleet management

## Building

### Offline engines (Linux/WSL or Windows via MSYS2)

```bash
mkdir build && cd build
cmake .. -G "MinGW Makefiles"   # omit -G on Linux
cmake --build .
```

This builds two targets:
- `dpi_engine` — single-threaded, reads a `.pcap` file
- `dpi_engine_mt` — multi-threaded version (dispatcher + worker pool)

### Live Windows agent (WinDivert)

Requires the WinDivert SDK (https://github.com/basil00/Divert/releases)
extracted somewhere on disk. From the same `build/` directory:

```bash
cmake .. -G "MinGW Makefiles" -DWINDIVERT_ROOT="C:/WinDivert-2.2.2-A"
cmake --build .
```

This additionally builds `dpi_agent.exe` in `build/windivert_agent/`, with
`WinDivert.dll` / `WinDivert64.sys` copied alongside it automatically.

Manual (non-CMake) build commands for each target are also documented
inline in `build.sh` and `windivert_agent/README.md`.

## Running

### Offline engine

```bash
# Generate a sample capture (requires: pip install scapy)
python3 generate_test_pcap.py

# Single-threaded
./dpi_engine test_traffic.pcap output.pcap --block-app YouTube --block-domain facebook

# Multi-threaded
./dpi_engine_mt test_traffic.pcap --workers 4 --block-app YouTube
```

### Live agent (Windows, run as Administrator)

```powershell
cd build\windivert_agent
.\dpi_agent.exe --block-domain youtube.com --block-domain googlevideo.com --block-domain ytimg.com --block-domain ggpht.com
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

## Multi-threaded version

`src/main_mt.cpp` implements the same pipeline with a dispatcher-thread +
worker-pool architecture. Each worker thread owns its own flow table (no
shared `unordered_map` between threads). The dispatcher hashes each
packet's five-tuple to consistently route it to the same worker every
time, so a single connection's state is only ever touched by one thread —
no locks needed in the classification hot path. The only synchronization
is a `ThreadSafeQueue` (mutex + condition variable) between the dispatcher
and each worker. Verified data-race-free with `-fsanitize=thread`.

## Live agent (WinDivert)

`windivert_agent/main_windivert.cpp` reuses `SNIExtractor` unchanged and
intercepts real outbound traffic on Windows via WinDivert:

- Intercepts outbound `tcp.DstPort == 443` (HTTPS) and `udp.DstPort == 443`
  (QUIC/HTTP-3).
- **QUIC is always dropped.** QUIC encrypts its handshake, so a domain
  can't be read out of it the way TLS-over-TCP can; dropping it forces
  browsers to fall back to inspectable TLS-over-TCP instead of silently
  bypassing the filter.
- TCP connections are classified via SNI extraction, same as the offline
  engine. Once a five-tuple is confirmed blocked, it's cached — every
  later packet in that connection is dropped too, since only the first
  packet of a connection ever carries a readable SNI.

See `windivert_agent/README.md` for full build/run instructions.

### Known limitation: HTTP/2 connection coalescing

Testing against real-world traffic (YouTube specifically) surfaced a
genuine architectural limit, not a bug:

- **QUIC (UDP:443) bypass** — fixed by dropping all outbound UDP:443,
  forcing fallback to inspectable TLS-over-TCP.
- **Multi-domain CDN footprints** — YouTube's actual content is served
  from `googlevideo.com`, `ytimg.com`, and `ggpht.com`, not just
  `youtube.com`. Fixed by blocking the full domain family.
- **No flow memory** — a TLS connection only reveals its SNI once, in
  the first packet. Fixed by caching classified five-tuples so every
  later packet in a blocked connection is dropped too, not just the
  handshake.
- **HTTP/2 connection coalescing (unresolved)** — browsers can reuse an
  already-open TLS connection for a new hostname if it's covered by the
  same certificate (common with large multi-domain providers like
  Google). No new ClientHello is sent, so no SNI is ever exposed for
  that hostname — it rides along on a connection already classified as
  allowed. This is invisible to any SNI-based filter, commercial or
  otherwise. Defeating it requires either full TLS interception (a fake
  root CA, decrypting traffic — a fundamentally different and more
  invasive architecture) or coarse IP/ASN-range blocking (blunt, and
  breaks unrelated services sharing those IPs). Both are legitimate
  future directions, but a different project from SNI inspection.

## Project structure

```
include/                 Header files (declarations)
  types.h                 FiveTuple, Flow, AppType
  pcap_reader.h            PCAP file format structs + reader
  packet_parser.h         Ethernet/IPv4/TCP/UDP parsing
  sni_extractor.h         TLS SNI + HTTP Host extraction
  thread_safe_queue.h     Mutex + condition-variable queue for the worker pool

src/                      Offline engine implementations
  pcap_reader.cpp
  packet_parser.cpp
  sni_extractor.cpp
  types.cpp
  main.cpp                Single-threaded entry point
  main_mt.cpp             Multi-threaded entry point (dispatcher + workers)

windivert_agent/          Live Windows traffic-blocking agent
  main_windivert.cpp       WinDivert capture/verdict loop
  sni_extractor.h/.cpp     Same SNI logic, reused unchanged
  CMakeLists.txt
  README.md                Full WinDivert setup/build/run instructions

CMakeLists.txt            Top-level build (all targets)
generate_test_pcap.py     Builds a sample capture for testing
build.sh                  Manual (non-CMake) build script for the offline engines
```

## Roadmap

Remaining work: a Node.js/Express API + MongoDB store for historical
stats, a React dashboard for live visualization, and Windows Service
packaging so the agent runs on boot across multiple devices without
manual admin launch.
