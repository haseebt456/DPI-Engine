#include "sni_extractor.h"
#include <cstring>

namespace {
uint16_t readU16BE(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}
}

// TLS ClientHello layout (TLS record + handshake, all big-endian):
//   [0]      Content Type        -- must be 0x16 (Handshake)
//   [1-2]    Legacy Version
//   [3-4]    Record Length
//   [5]      Handshake Type      -- must be 0x01 (ClientHello)
//   [6-8]    Handshake Length (3 bytes)
//   [9-10]   Client Version
//   [11-42]  Random (32 bytes)
//   [43]     Session ID Length (N)      -- followed by N bytes of session id
//   [..]     Cipher Suites Length (2)   -- followed by that many bytes
//   [..]     Compression Methods Length (1) -- followed by that many bytes
//   [..]     Extensions Length (2)      -- followed by a list of extensions
// Each extension is: type(2) + length(2) + data(length)
// The SNI extension has type 0x0000, and inside it, after a couple of
// nested length fields, sits the actual hostname.
std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (length < 43) return std::nullopt;

    if (payload[0] != 0x16) return std::nullopt; // not a TLS Handshake record
    if (payload[5] != 0x01) return std::nullopt; // not a ClientHello

    size_t offset = 9;
    offset += 2;  // client_version
    offset += 32; // random

    if (offset >= length) return std::nullopt;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_len = readU16BE(payload + offset);
    offset += 2 + cipher_suites_len;

    if (offset + 1 > length) return std::nullopt;
    uint8_t compression_methods_len = payload[offset];
    offset += 1 + compression_methods_len;

    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_len = readU16BE(payload + offset);
    offset += 2;

    size_t extensions_end = offset + extensions_len;
    if (extensions_end > length) extensions_end = length;

    while (offset + 4 <= extensions_end) {
        uint16_t ext_type = readU16BE(payload + offset);
        uint16_t ext_len  = readU16BE(payload + offset + 2);
        size_t ext_data_start = offset + 4;

        if (ext_type == 0x0000) { // server_name extension
            // Inside: server_name_list_len(2) + type(1) + name_len(2) + name
            if (ext_data_start + 5 <= length) {
                uint16_t name_len = readU16BE(payload + ext_data_start + 3);
                size_t name_start = ext_data_start + 5;
                if (name_start + name_len <= length) {
                    return std::string(reinterpret_cast<const char*>(payload + name_start), name_len);
                }
            }
            return std::nullopt;
        }

        offset = ext_data_start + ext_len;
    }

    return std::nullopt; // no SNI extension present
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    static const char* methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE "};
    bool looks_like_http = false;
    for (const char* m : methods) {
        size_t mlen = strlen(m);
        if (length >= mlen && memcmp(payload, m, mlen) == 0) {
            looks_like_http = true;
            break;
        }
    }
    if (!looks_like_http) return std::nullopt;

    std::string text(reinterpret_cast<const char*>(payload), length);
    size_t pos = text.find("Host: ");
    if (pos == std::string::npos) return std::nullopt;

    size_t start = pos + 6;
    size_t end = text.find("\r\n", start);
    if (end == std::string::npos) end = text.find('\n', start);
    if (end == std::string::npos) return std::nullopt;

    return text.substr(start, end - start);
}
