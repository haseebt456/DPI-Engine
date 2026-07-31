#include "packet_parser.h"
#include <cstdio>

namespace {

uint16_t readU16BE(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

uint32_t readU32BE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
            static_cast<uint32_t>(p[3]);
}

std::string macToString(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string ipToString(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 24) & 0xFFu, (ip >> 16) & 0xFFu, (ip >> 8) & 0xFFu, ip & 0xFFu);
    return std::string(buf);
}

} // namespace

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    const auto& data = raw.data;

    // --- Ethernet header: 14 bytes ---
    // [0-5] dest MAC, [6-11] src MAC, [12-13] EtherType
    if (data.size() < 14) return false;
    const uint8_t* p = data.data();

    parsed.dest_mac = macToString(p);
    parsed.src_mac  = macToString(p + 6);
    uint16_t ether_type = readU16BE(p + 12);

    if (ether_type != 0x0800) {
        return false; // Only IPv4 handled here; ARP/IPv6 skipped for scope
    }

    // --- IPv4 header: 20+ bytes ---
    // byte 0: version(4 bits) + IHL(4 bits) -- IHL is header length in 32-bit words
    // byte 9: protocol (6 = TCP, 17 = UDP)
    // bytes 12-15: src IP, bytes 16-19: dst IP
    size_t ip_offset = 14;
    if (data.size() < ip_offset + 20) return false;

    const uint8_t* ip = p + ip_offset;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20) return false; // malformed header length

    parsed.protocol   = ip[9];
    parsed.src_ip     = readU32BE(ip + 12);
    parsed.dest_ip    = readU32BE(ip + 16);
    parsed.src_ip_str = ipToString(parsed.src_ip);
    parsed.dest_ip_str = ipToString(parsed.dest_ip);

    size_t transport_offset = ip_offset + ihl;

    if (parsed.protocol == 6) {
        // --- TCP header: 20+ bytes ---
        // bytes 0-1 src port, bytes 2-3 dst port
        // byte 12 top nibble = data offset (header length in 32-bit words)
        if (data.size() < transport_offset + 20) return false;
        const uint8_t* tcp = p + transport_offset;
        parsed.src_port  = readU16BE(tcp);
        parsed.dest_port = readU16BE(tcp + 2);
        uint8_t data_offset = ((tcp[12] & 0xF0) >> 4) * 4;
        parsed.has_tcp = true;
        parsed.payload_offset = transport_offset + data_offset;
    } else if (parsed.protocol == 17) {
        // --- UDP header: fixed 8 bytes ---
        if (data.size() < transport_offset + 8) return false;
        const uint8_t* udp = p + transport_offset;
        parsed.src_port  = readU16BE(udp);
        parsed.dest_port = readU16BE(udp + 2);
        parsed.has_udp = true;
        parsed.payload_offset = transport_offset + 8;
    } else {
        parsed.payload_offset = transport_offset; // unhandled protocol
    }

    parsed.payload_length =
        (parsed.payload_offset <= data.size()) ? (data.size() - parsed.payload_offset) : 0;

    return true;
}
