#include <iostream>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <cstdint>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <vector>
#include <utility>
#include "sni_extractor.h"
#include "http_client.h"
#include "config.h"
#include "json_mini.h"
#include "thread_safe_queue.h"

#define WIN32_LEAN_AND_MEAN
#include <windivert.h>

namespace {

uint16_t readU16BE(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

struct Rules {
    std::unordered_set<std::string> blocked_domains;
    bool isBlocked(const std::string& sni) const {
        for (const auto& d : blocked_domains) {
            if (sni.find(d) != std::string::npos) return true;
        }
        return false;
    }
};

std::mutex rules_mutex;
Rules current_rules;
std::atomic<bool> running{true};
ThreadSafeQueue<std::pair<std::string, std::string>> event_queue; // domain, action

bool doEnroll(const std::string& server_url, const std::string& pairing_code, const std::string& config_path) {
    auto resp = HttpClient::post(server_url + "/api/devices/enroll", JsonMini::buildEnrollBody(pairing_code));
    if (!resp.success) {
        std::cerr << "Enrollment failed (HTTP " << resp.status_code << "): " << resp.body << "\n";
        return false;
    }

    std::string device_id, api_key;
    if (!JsonMini::extractStringField(resp.body, "apiKey", api_key)) {
        std::cerr << "Enrollment response missing apiKey: " << resp.body << "\n";
        return false;
    }
    // deviceId comes back as a number, not a string -- extract it manually.
    size_t pos = resp.body.find("\"deviceId\"");
    if (pos == std::string::npos) {
        std::cerr << "Enrollment response missing deviceId: " << resp.body << "\n";
        return false;
    }
    size_t colon = resp.body.find(':', pos);
    size_t start = colon + 1;
    size_t end = resp.body.find_first_of(",}", start);
    device_id = resp.body.substr(start, end - start);
    // trim whitespace
    device_id.erase(0, device_id.find_first_not_of(" \t"));
    device_id.erase(device_id.find_last_not_of(" \t") + 1);

    AgentConfig cfg{server_url, device_id, api_key};
    if (!ConfigStore::save(config_path, cfg)) {
        std::cerr << "Failed to write config file: " << config_path << "\n";
        return false;
    }

    std::cout << "Enrolled successfully. deviceId=" << device_id << "\n";
    return true;
}

void rulePollLoop(const AgentConfig& cfg) {
    while (running) {
        auto resp = HttpClient::get(cfg.server_url + "/api/rules/for-device/" + cfg.device_id, cfg.api_key);
        if (resp.success) {
            auto entries = JsonMini::parseRulesArray(resp.body);
            Rules updated;
            for (const auto& e : entries) {
                if (e.type == "domain") updated.blocked_domains.insert(e.value);
            }
            {
                std::lock_guard<std::mutex> lock(rules_mutex);
                current_rules = updated;
            }
            std::cout << "[poll] fetched " << entries.size() << " rule(s)\n";
        } else {
            std::cout << "[poll] failed (HTTP " << resp.status_code << ")\n";
        }
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
}

void eventReportLoop(const AgentConfig& cfg) {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        std::vector<std::pair<std::string, std::string>> batch;
        while (batch.size() < 50) {
            auto item = event_queue.try_pop();
            if (!item) break;
            batch.push_back(*item);
        }
        if (!batch.empty()) {
            auto resp = HttpClient::post(cfg.server_url + "/api/events/" + cfg.device_id,
                                          JsonMini::buildEventsBody(batch), cfg.api_key);
            std::cout << "[report] sent " << batch.size() << " event(s), success=" << resp.success << "\n";
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string config_path = "agent_config.txt";

    // --- Enrollment mode: run once, then exit ---
    if (argc >= 3 && std::string(argv[1]) == "--enroll") {
        std::string pairing_code = argv[2];
        std::string server_url = "http://localhost:4000";
        for (int i = 3; i < argc; i++) {
            if (std::string(argv[i]) == "--server" && i + 1 < argc) server_url = argv[++i];
        }
        return doEnroll(server_url, pairing_code, config_path) ? 0 : 1;
    }

    // --- Normal run mode ---
    AgentConfig cfg;
    if (!ConfigStore::load(config_path, cfg)) {
        std::cerr << "No valid config found. Run enrollment first:\n"
                  << "  " << argv[0] << " --enroll <pairingCode> --server http://<ip>:4000\n";
        return 1;
    }

    std::thread poll_thread(rulePollLoop, cfg);
    std::thread report_thread(eventReportLoop, cfg);

    HANDLE handle = WinDivertOpen("outbound and (tcp.DstPort == 443 or udp.DstPort == 443)",
                                   WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle (error " << GetLastError()
                  << "). Are you running as Administrator?\n";
        running = false;
        event_queue.shutdown();
        poll_thread.join();
        report_thread.join();
        return 1;
    }

    std::cout << "DPI agent running (server-managed rules). Press Ctrl+C to stop.\n";

    unsigned char packet[WINDIVERT_MTU_MAX];
    WINDIVERT_ADDRESS addr;
    UINT recv_len;

    while (running) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_len, &addr)) continue;

        bool block = false;

        if (recv_len >= 20) {
            uint8_t ihl = (packet[0] & 0x0F) * 4;
            uint8_t protocol = packet[9];

            if (protocol == 17) {
                block = true; // QUIC -- always drop, forces TCP fallback
            } else if (protocol == 6 && recv_len >= static_cast<UINT>(ihl) + 20) {
                const unsigned char* tcp = packet + ihl;
                uint8_t data_offset = ((tcp[12] & 0xF0) >> 4) * 4;
                size_t payload_offset = static_cast<size_t>(ihl) + data_offset;

                if (payload_offset < recv_len) {
                    auto sni = SNIExtractor::extract(packet + payload_offset, recv_len - payload_offset);
                    if (sni) {
                        std::lock_guard<std::mutex> lock(rules_mutex);
                        if (current_rules.isBlocked(*sni)) {
                            std::cout << "BLOCKED: " << *sni << "\n";
                            event_queue.push({*sni, "blocked"});
                            block = true;
                        }
                    }
                }
            }
        }

        if (!block) WinDivertSend(handle, packet, recv_len, nullptr, &addr);
    }

    WinDivertClose(handle);
    running = false;
    event_queue.shutdown();
    poll_thread.join();
    report_thread.join();
    return 0;
}