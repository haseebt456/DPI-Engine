#include "pcap_reader.h"

namespace {
uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}
}

bool PcapReader::open(const std::string& filename) {
    file_ = fopen(filename.c_str(), "rb");
    if (!file_) return false;

    PcapGlobalHeader gh;
    if (fread(&gh, sizeof(gh), 1, file_) != 1) {
        fclose(file_);
        file_ = nullptr;
        return false;
    }

    // 0xa1b2c3d4 is the standard pcap magic number written in native order.
    // 0xd4c3b2a1 is the same bytes read on a machine with the opposite
    // endianness -- we detect that case and byte-swap every header field.
    if (gh.magic_number == 0xa1b2c3d4) {
        swapped_ = false;
    } else if (gh.magic_number == 0xd4c3b2a1) {
        swapped_ = true;
    } else {
        fclose(file_);
        file_ = nullptr;
        return false; // not a valid pcap file
    }

    return true;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (!file_) return false;

    PcapPacketHeader ph;
    if (fread(&ph, sizeof(ph), 1, file_) != 1) {
        return false; // EOF or truncated file
    }

    if (swapped_) {
        ph.ts_sec    = swap32(ph.ts_sec);
        ph.ts_usec   = swap32(ph.ts_usec);
        ph.incl_len  = swap32(ph.incl_len);
        ph.orig_len  = swap32(ph.orig_len);
    }

    packet.header = ph;
    packet.data.resize(ph.incl_len);

    if (ph.incl_len > 0) {
        if (fread(packet.data.data(), 1, ph.incl_len, file_) != ph.incl_len) {
            return false; // truncated packet data
        }
    }

    return true;
}

void PcapReader::close() {
    if (file_) {
        fclose(file_);
        file_ = nullptr;
    }
}

PcapReader::~PcapReader() {
    close();
}
