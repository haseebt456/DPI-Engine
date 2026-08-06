#include "config.h"
#include <fstream>

namespace {
std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}
}

bool ConfigStore::load(const std::string& path, AgentConfig& out) {
    std::ifstream in(path);
    if (!in) return false;

    std::string line;
    while (std::getline(in, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string value = trim(line.substr(eq + 1));
        if (key == "server_url") out.server_url = value;
        else if (key == "device_id") out.device_id = value;
        else if (key == "api_key") out.api_key = value;
    }
    return !out.device_id.empty() && !out.api_key.empty();
}

bool ConfigStore::save(const std::string& path, const AgentConfig& cfg) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    out << "server_url=" << cfg.server_url << "\n";
    out << "device_id=" << cfg.device_id << "\n";
    out << "api_key=" << cfg.api_key << "\n";
    return true;
}