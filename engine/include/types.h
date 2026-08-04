#pragma once
#include <cstdint>
#include <string>
#include <functional>

// The set of applications we can recognize from TLS SNI / HTTP Host header.
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    YOUTUBE,
    FACEBOOK,
    GOOGLE,
    GITHUB,
    TWITTER,
    NETFLIX
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

// A network connection is uniquely identified by these 5 fields.
// Packets sharing the same FiveTuple belong to the same "flow".
struct FiveTuple {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0; // 6 = TCP, 17 = UDP

    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

// Lets FiveTuple be used as a key in std::unordered_map.
struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& t) const {
        auto combine = [](std::size_t seed, std::size_t v) {
            return seed ^ (v + 0x9e3779b9 + (seed << 6) + (seed >> 2));
        };
        std::size_t seed = std::hash<uint32_t>()(t.src_ip);
        seed = combine(seed, std::hash<uint32_t>()(t.dst_ip));
        seed = combine(seed, std::hash<uint16_t>()(t.src_port));
        seed = combine(seed, std::hash<uint16_t>()(t.dst_port));
        seed = combine(seed, std::hash<uint8_t>()(t.protocol));
        return seed;
    }
};

// State we track per connection.
struct Flow {
    FiveTuple tuple;
    std::string sni;             // domain name extracted from TLS/HTTP, if any
    AppType app_type = AppType::UNKNOWN;
    bool blocked = false;
    uint32_t packet_count = 0;
    uint64_t byte_count = 0;
};
