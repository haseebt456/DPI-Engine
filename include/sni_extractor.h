#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>

// Pulls the domain name out of a TLS ClientHello's SNI extension.
// This is possible because SNI is sent in plaintext, before encryption
// keys are negotiated -- the one place HTTPS traffic reveals its destination.
class SNIExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
};

// Pulls the domain name out of a plaintext HTTP "Host:" header.
class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
};
