#pragma once
#include "pcap_reader.h"
#include <cstdint>
#include <string>

// Fields extracted after walking Ethernet -> IPv4 -> TCP/UDP headers.
struct ParsedPacket {
    std::string src_mac;
    std::string dest_mac;
    std::string src_ip_str;
    std::string dest_ip_str;
    uint32_t src_ip = 0;
    uint32_t dest_ip = 0;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    uint8_t  protocol = 0; // 6 = TCP, 17 = UDP
    bool has_tcp = false;
    bool has_udp = false;
    size_t payload_offset = 0; // where the application-layer data starts
    size_t payload_length = 0;
};

class PacketParser {
public:
    // Returns false if the packet is too short, malformed, or not IPv4.
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);
};
