#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

// Layout of a .pcap file's 24-byte global header.
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network; // 1 = Ethernet
};

// Every packet in the file is preceded by one of these 16-byte headers.
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len; // bytes actually captured (may be < orig_len)
    uint32_t orig_len; // original length on the wire
};

struct RawPacket {
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    bool open(const std::string& filename);
    bool readNextPacket(RawPacket& packet);
    void close();
    ~PcapReader();

private:
    FILE* file_ = nullptr;
    bool swapped_ = false; // true if the file's byte order differs from ours
};
