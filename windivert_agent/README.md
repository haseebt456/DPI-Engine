# DPI Agent (Live Version) — Windows / WinDivert

This is the live-traffic version of the DPI engine. Unlike the offline
`.pcap`-file version, this program runs on **your real Windows machine**,
intercepts your actual outbound HTTPS connection attempts, and blocks the
ones matching your rules — in real time.

It reuses `SNIExtractor` unchanged from the offline engine (`sni_extractor.h`
/ `sni_extractor.cpp`) — same TLS ClientHello parsing logic, just fed by
live traffic instead of a file.

## Prerequisites

1. **WinDivert** — download the pre-built package from
   https://github.com/basil00/Divert/releases (grab the latest
   `WinDivert-2.x.x-A.zip`). Extract it somewhere, e.g. `C:\WinDivert`.
2. **MSYS2** (for a native Windows compiler) — https://www.msys2.org
   Then in the "MSYS2 MinGW64" terminal:
   ```
   pacman -S mingw-w64-x86_64-gcc
   ```

**Important:** this must be built and run on the **Windows side**, not
inside WSL. WinDivert is a Windows kernel driver — it can't be reached from
a Linux binary running in WSL.

## Building

Open the "MSYS2 MinGW64" terminal, `cd` into this folder, then (adjust the
WinDivert path to wherever you extracted it):

```bash
g++ -std=c++17 -O2 \
    -I /c/WinDivert/include \
    -o dpi_agent.exe main_windivert.cpp sni_extractor.cpp \
    -L /c/WinDivert/x64 -lWinDivert
```

Then copy these two files from the WinDivert package into the same folder
as `dpi_agent.exe`:
- `WinDivert.dll`
- `WinDivert64.sys` (or `WinDivert32.sys` if you're on 32-bit Windows)

## Running

Open a terminal **as Administrator** (WinDivert requires it — right-click
your terminal, "Run as administrator"), then:

```
dpi_agent.exe --block-domain youtube.com --block-domain facebook.com
```

Now open a browser and try visiting youtube.com — the connection should
time out / fail to load, while everything else keeps working normally.
Every blocked attempt prints to the console.

Press Ctrl+C to stop (this also silently uninstalls the WinDivert driver
hook — nothing persists after the process exits).

## What's different from the offline engine

| | Offline engine (`dpi_engine`) | Live agent (`dpi_agent`) |
|---|---|---|
| Input | `.pcap` file | Real live traffic |
| Layer parsed | Ethernet + IPv4 + TCP/UDP | IPv4 + TCP only (WinDivert already strips Ethernet) |
| Platform | Linux/WSL | Windows only |
| Effect | None (read-only analysis) | Actually blocks real connections |
| Scope | Any protocol, any port | Currently outbound TCP/443 only |

## Known limitations (current scope)

- Only handles HTTPS (port 443) via SNI — no plain HTTP blocking yet
- Only blocks by domain substring — no `--block-app` / `--block-ip` yet
  (easy to add later, same `Rules` pattern as the offline engine)
- No logging to file, no persistence between runs
- Must be manually run as Administrator each time (this is exactly what
  the Windows Service step in the roadmap will fix)

## Next steps (per the project roadmap)

1. Verify this works reliably on your own machine first
2. Wrap it as a Windows Service (via NSSM) so it runs on boot without
   manual admin launch
3. Add the polling/reporting threads to talk to the central server
