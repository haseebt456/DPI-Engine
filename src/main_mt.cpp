// Multi-threaded version of the DPI engine.
//
// Architecture:
//   [Dispatcher thread] --parses headers, hashes five-tuple--> [Worker 0..N-1]
//
// Each worker owns its own flow table and its own stats -- no shared state
// between workers, so no locks are needed *inside* the hot classification
// path. The only synchronization is at the ThreadSafeQueue boundary.
//
// Packets from the same connection (same five-tuple) always hash to the
// same worker, so a single flow's state is never touched by two threads.

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "thread_safe_queue.h"
#include "types.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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

// One unit of work handed from the dispatcher to a worker. The dispatcher
// has already parsed the headers (cheap) so the worker can go straight to
// classification without redoing that work.
struct WorkItem {
    RawPacket raw;
    ParsedPacket parsed;
};

// Everything a single worker accumulates. Kept entirely local to one
// thread -- merged into a grand total only after all workers finish.
struct WorkerStats {
    uint32_t packets_seen = 0;
    uint32_t tcp_packets = 0;
    uint32_t udp_packets = 0;
    uint32_t forwarded = 0;
    uint32_t dropped = 0;
    std::unordered_map<AppType, uint32_t> app_stats;
    std::vector<std::pair<std::string, std::pair<AppType, bool>>> detected_domains; // sni -> (app, blocked)
};

void workerLoop(int worker_id, ThreadSafeQueue<WorkItem>& queue,
                 const Rules& rules, WorkerStats& stats) {
    // Each worker has its OWN flow table. Because five-tuple hashing
    // guarantees a given connection's packets always land here, this map
    // never needs a mutex -- only this thread ever touches it.
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;

    while (auto item = queue.pop()) {
        WorkItem& work = *item;
        stats.packets_seen++;
        if (work.parsed.has_tcp) stats.tcp_packets++;
        if (work.parsed.has_udp) stats.udp_packets++;

        FiveTuple tuple{work.parsed.src_ip, work.parsed.dest_ip,
                         work.parsed.src_port, work.parsed.dest_port, work.parsed.protocol};
        Flow& flow = flows[tuple];
        flow.tuple = tuple;
        flow.packet_count++;
        flow.byte_count += work.raw.data.size();

        if (flow.sni.empty() && work.parsed.payload_length > 5 &&
            work.parsed.payload_offset < work.raw.data.size()) {
            const uint8_t* payload = work.raw.data.data() + work.parsed.payload_offset;
            size_t payload_len = work.parsed.payload_length;

            if (work.parsed.dest_port == 443 || work.parsed.src_port == 443) {
                auto sni = SNIExtractor::extract(payload, payload_len);
                if (sni) {
                    flow.sni = *sni;
                    flow.app_type = sniToAppType(*sni);
                    stats.detected_domains.push_back({flow.sni, {flow.app_type, false}});
                }
            } else if (work.parsed.dest_port == 80 || work.parsed.src_port == 80) {
                auto host = HTTPHostExtractor::extract(payload, payload_len);
                if (host) {
                    flow.sni = *host;
                    flow.app_type = AppType::HTTP;
                    stats.detected_domains.push_back({flow.sni, {flow.app_type, false}});
                }
            }
        }

        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(work.parsed.src_ip_str, flow.app_type, flow.sni);
            if (flow.blocked && !stats.detected_domains.empty()) {
                stats.detected_domains.back().second.second = true;
            }
        }

        if (flow.blocked) {
            stats.dropped++;
        } else {
            stats.forwarded++;
        }

        stats.app_stats[flow.app_type]++;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <input.pcap> [--workers N] [--block-app NAME] "
                     "[--block-ip IP] [--block-domain DOMAIN]\n";
        return 1;
    }

    std::string input_file = argv[1];
    Rules rules;
    unsigned int num_workers = std::max(2u, std::thread::hardware_concurrency());

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--workers" && i + 1 < argc) {
            num_workers = std::stoul(argv[++i]);
        } else if (arg == "--block-app" && i + 1 < argc) {
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

    std::cout << "Starting " << num_workers << " worker threads...\n";

    std::vector<ThreadSafeQueue<WorkItem>> queues(num_workers);
    std::vector<WorkerStats> worker_stats(num_workers);
    std::vector<std::thread> workers;

    for (unsigned int i = 0; i < num_workers; i++) {
        workers.emplace_back(workerLoop, i, std::ref(queues[i]), std::cref(rules),
                              std::ref(worker_stats[i]));
    }

    // --- Dispatcher: runs on the main thread ---
    uint32_t total_packets = 0, unparsed_packets = 0;
    uint64_t total_bytes = 0;

    RawPacket raw;
    while (reader.readNextPacket(raw)) {
        total_packets++;
        total_bytes += raw.data.size();

        ParsedPacket parsed;
        if (!PacketParser::parse(raw, parsed)) {
            unparsed_packets++;
            continue; // not IPv4, or malformed -- nothing to route
        }

        FiveTuple tuple{parsed.src_ip, parsed.dest_ip, parsed.src_port,
                         parsed.dest_port, parsed.protocol};
        size_t worker_id = FiveTupleHash{}(tuple) % num_workers;

        WorkItem item{std::move(raw), parsed};
        queues[worker_id].push(std::move(item));

        raw = RawPacket{}; // reset for the next read
    }
    reader.close();

    // No more work is coming -- tell every worker to drain and exit.
    for (auto& q : queues) q.shutdown();
    for (auto& t : workers) t.join();

    // --- Merge results from all workers ---
    WorkerStats merged;
    for (unsigned int i = 0; i < num_workers; i++) {
        const auto& s = worker_stats[i];
        merged.packets_seen += s.packets_seen;
        merged.tcp_packets += s.tcp_packets;
        merged.udp_packets += s.udp_packets;
        merged.forwarded += s.forwarded;
        merged.dropped += s.dropped;
        for (const auto& [app, count] : s.app_stats) merged.app_stats[app] += count;
        for (const auto& d : s.detected_domains) merged.detected_domains.push_back(d);

        std::cout << "  Worker " << i << ": " << s.packets_seen << " packets, "
                  << s.forwarded << " forwarded, " << s.dropped << " dropped\n";
    }

    std::cout << "\n=== PROCESSING REPORT (merged across " << num_workers << " workers) ===\n";
    std::cout << "Total Packets:    " << total_packets << " (unparsed: " << unparsed_packets << ")\n";
    std::cout << "Total Bytes:      " << total_bytes << "\n";
    std::cout << "TCP Packets:      " << merged.tcp_packets << "\n";
    std::cout << "UDP Packets:      " << merged.udp_packets << "\n";
    std::cout << "Forwarded:        " << merged.forwarded << "\n";
    std::cout << "Dropped:          " << merged.dropped << "\n";

    std::cout << "\n=== APPLICATION BREAKDOWN ===\n";
    for (const auto& [app, count] : merged.app_stats) {
        double pct = merged.packets_seen ? (100.0 * count / merged.packets_seen) : 0.0;
        std::cout << std::left << std::setw(10) << appTypeToString(app)
                  << count << " packets (" << std::fixed << std::setprecision(1) << pct << "%)\n";
    }

    std::cout << "\n=== DETECTED DOMAINS ===\n";
    for (const auto& [sni, info] : merged.detected_domains) {
        std::cout << "  " << sni << " -> " << appTypeToString(info.first);
        if (info.second) std::cout << "  (BLOCKED)";
        std::cout << "\n";
    }

    return 0;
}
