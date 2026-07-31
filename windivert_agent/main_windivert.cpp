// DPI Agent - live version, Windows-only.
//
// Unlike the pcap-file version, this program intercepts REAL outbound
// traffic from this machine using WinDivert, checks the destination domain
// (via TLS SNI, reusing the same extractor from the offline engine), and
// either lets the packet continue or silently drops it.
//
// Build (MSYS2 MinGW64 terminal, from this directory):
//   g++ -std=c++17 -O2 -I <path-to-windivert>\include -o dpi_agent.exe ^
//       main_windivert.cpp sni_extractor.cpp ^
//       -L <path-to-windivert>\x64 -lWinDivert
//
// Then copy WinDivert.dll and WinDivert64.sys next to dpi_agent.exe.
//
// Run (MUST be Administrator):
//   dpi_agent.exe --block-domain youtube.com --block-domain facebook.com



#include <iostream>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <cstdint>
#include "sni_extractor.h"
#define WIN32_LEAN_AND_MEAN
#include <windivert.h>

namespace {

uint16_t readU16BE(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

// Simple domain-substring block list. Same idea as the offline engine's
// Rules struct, trimmed down to just what the live agent needs for now.
struct Rules {
    std::unordered_set<std::string> blocked_domains;

    bool isBlocked(const std::string& sni) const {
        for (const auto& d : blocked_domains) {
            if (sni.find(d) != std::string::npos) return true;
        }
        return false;
    }
};

} // namespace

int main(int argc, char** argv) {
    Rules rules;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-domain" && i + 1 < argc) {
            rules.blocked_domains.insert(argv[++i]);
        }
    }

    if (rules.blocked_domains.empty()) {
        std::cerr << "Usage: " << argv[0] << " --block-domain <domain> [--block-domain <domain> ...]\n";
        return 1;
    }

    // Only intercept outbound TCP traffic headed to port 443 (HTTPS).
    // Everything else passes through the kernel untouched -- we never see it,
    // so we never slow it down.
    HANDLE handle = WinDivertOpen("outbound and (tcp.DstPort == 443 or udp.DstPort == 443)",
                                   WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle (error " << GetLastError()
                  << "). Are you running as Administrator?\n";
        return 1;
    }

    std::cout << "DPI agent running. Blocking:";
    for (const auto& d : rules.blocked_domains) std::cout << " " << d;
    std::cout << "\nPress Ctrl+C to stop.\n";

    unsigned char packet[WINDIVERT_MTU_MAX];
    WINDIVERT_ADDRESS addr;
    UINT recv_len;

    while (true) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_len, &addr)) {
            continue; // transient error, just keep going
        }

        bool block = false;

        // At WINDIVERT_LAYER_NETWORK the buffer starts directly at the IPv4
        // header -- there's no Ethernet header here (WinDivert already
        // stripped that layer for us).
        if (recv_len >= 20) {
            uint8_t ihl = (packet[0] & 0x0F) * 4;
            uint8_t protocol = packet[9];

            if(protocol == 17){
                // QUIC (UDP:443) -- always drop. See the comment above
                // WinDivertOpen() for why: we can't read the domain out of
                // an encrypted QUIC handshake, so we close the bypass
                // instead, forcing a fallback to TCP where we CAN inspect it.
                char ip_buf[16];
                snprintf(ip_buf, sizeof(ip_buf), "%u.%u.%u.%u",
                         packet[16], packet[17], packet[18], packet[19]);
                std::cout << "DROPPED UDP:443 (QUIC) -> " << ip_buf << "\n";
                block = true;
            }else if (protocol == 6 && recv_len >= static_cast<UINT>(ihl) + 20) {
                const unsigned char* tcp = packet + ihl;
                uint8_t data_offset = ((tcp[12] & 0xF0) >> 4) * 4;
                size_t payload_offset = static_cast<size_t>(ihl) + data_offset;

                if (payload_offset < recv_len) {
                    auto sni = SNIExtractor::extract(packet + payload_offset,
                                                      recv_len - payload_offset);
                    if (sni && rules.isBlocked(*sni)) {
                        std::cout << "BLOCKED: " << *sni << "\n";
                        block = true;
                    }
                }
            }
        }

        if (!block) {
            // Re-inject the packet unmodified so it continues on its way.
            WinDivertSend(handle, packet, recv_len, nullptr, &addr);
        }
        // If blocked, we simply don't call WinDivertSend -- the packet
        // is dropped, and that connection attempt will time out.
    }

    WinDivertClose(handle);
    return 0;
}
