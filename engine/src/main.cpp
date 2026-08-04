#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <unordered_set>


// Blocking rules: by source IP, by recognized app, or by domain substring.
struct Rules {
    std::unordered_set<std::string> blocked_ips;
    std::unordered_set<std::string> blocked_domains;
    std::unordered_set<AppType> blocked_apps;

    bool isBlocked(const std::string& src_ip, AppType app, const std::string& sni) const {
        if (blocked_ips.count(src_ip)) return true;
        if (blocked_apps.count(app)) return true;
        for (const auto& dom : blocked_domains) {
            if (!sni.empty() && sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }
};

static AppType parseAppName(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "youtube")  return AppType::YOUTUBE;
    if (lower == "facebook") return AppType::FACEBOOK;
    if (lower == "google")   return AppType::GOOGLE;
    if (lower == "github")   return AppType::GITHUB;
    if (lower == "twitter")  return AppType::TWITTER;
    if (lower == "netflix")  return AppType::NETFLIX;
    return AppType::UNKNOWN;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <input.pcap> <output.pcap> "
                     "[--block-app NAME] [--block-ip IP] [--block-domain DOMAIN]\n";
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    Rules rules;
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-app" && i + 1 < argc) {
            rules.blocked_apps.insert(parseAppName(argv[++i]));
        } else if (arg == "--block-ip" && i + 1 < argc) {
            rules.blocked_ips.insert(argv[++i]);
        } else if (arg == "--block-domain" && i + 1 < argc) {
            rules.blocked_domains.insert(argv[++i]);
        }
    }

    PcapReader reader;
    if (!reader.open(input_file)) {
        std::cerr << "Failed to open input file: " << input_file << "\n";
        return 1;
    }

    std::ofstream out(output_file, std::ios::binary);
    if (!out) {
        std::cerr << "Failed to open output file: " << output_file << "\n";
        return 1;
    }

    // Write a fresh global header for the output pcap (Ethernet link type).
    PcapGlobalHeader gh{};
    gh.magic_number  = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone      = 0;
    gh.sigfigs       = 0;
    gh.snaplen       = 65535;
    gh.network       = 1;
    out.write(reinterpret_cast<char*>(&gh), sizeof(gh));

    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;
    std::unordered_map<AppType, uint32_t> app_stats;

    uint32_t total_packets = 0, tcp_packets = 0, udp_packets = 0;
    uint32_t forwarded = 0, dropped = 0;
    uint64_t total_bytes = 0;

    RawPacket raw;
    while (reader.readNextPacket(raw)) {
        total_packets++;
        total_bytes += raw.data.size();

        ParsedPacket parsed;
        bool ok = PacketParser::parse(raw, parsed);
        bool blocked = false;

        if (ok) {
            if (parsed.has_tcp) tcp_packets++;
            if (parsed.has_udp) udp_packets++;

            FiveTuple tuple{parsed.src_ip, parsed.dest_ip,
                             parsed.src_port, parsed.dest_port, parsed.protocol};
            Flow& flow = flows[tuple]; // get-or-create: same tuple -> same flow
            flow.tuple = tuple;
            flow.packet_count++;
            flow.byte_count += raw.data.size();

            // Only bother inspecting the payload if there's enough of it
            // and it hasn't already been classified.
            if (flow.sni.empty() && parsed.payload_length > 5 &&
                parsed.payload_offset < raw.data.size()) {
                const uint8_t* payload = raw.data.data() + parsed.payload_offset;
                size_t payload_len = parsed.payload_length;

                if (parsed.dest_port == 443 || parsed.src_port == 443) {
                    auto sni = SNIExtractor::extract(payload, payload_len);
                    if (sni) {
                        flow.sni = *sni;
                        flow.app_type = sniToAppType(*sni);
                    }
                } else if (parsed.dest_port == 80 || parsed.src_port == 80) {
                    auto host = HTTPHostExtractor::extract(payload, payload_len);
                    if (host) {
                        flow.sni = *host;
                        flow.app_type = AppType::HTTP;
                    }
                }
            }

            // Once a flow is marked blocked, every subsequent packet in it
            // is dropped too -- we don't re-evaluate rules every packet.
            if (!flow.blocked) {
                flow.blocked = rules.isBlocked(parsed.src_ip_str, flow.app_type, flow.sni);
            }
            blocked = flow.blocked;
            app_stats[flow.app_type]++;
        }

        if (blocked) {
            dropped++;
        } else {
            forwarded++;
            out.write(reinterpret_cast<char*>(&raw.header), sizeof(raw.header));
            out.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }

    reader.close();
    out.close();

    std::cout << "\n=== PROCESSING REPORT ===\n";
    std::cout << "Total Packets: " << total_packets << "\n";
    std::cout << "Total Bytes:   " << total_bytes << "\n";
    std::cout << "TCP Packets:   " << tcp_packets << "\n";
    std::cout << "UDP Packets:   " << udp_packets << "\n";
    std::cout << "Forwarded:     " << forwarded << "\n";
    std::cout << "Dropped:       " << dropped << "\n";

    std::cout << "\n=== APPLICATION BREAKDOWN ===\n";
    for (const auto& [app, count] : app_stats) {
        double pct = total_packets ? (100.0 * count / total_packets) : 0.0;
        std::cout << std::left << std::setw(10) << appTypeToString(app)
                  << count << " packets (" << std::fixed << std::setprecision(1) << pct << "%)\n";
    }

    std::cout << "\n=== DETECTED DOMAINS ===\n";
    for (const auto& [tuple, flow] : flows) {
        if (!flow.sni.empty()) {
            std::cout << "  " << flow.sni << " -> " << appTypeToString(flow.app_type);
            if (flow.blocked) std::cout << "  (BLOCKED)";
            std::cout << "\n";
        }
    }

    return 0;
}
