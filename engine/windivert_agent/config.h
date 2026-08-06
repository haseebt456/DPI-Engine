#pragma once
#include <string>

struct AgentConfig {
    std::string server_url;
    std::string device_id;
    std::string api_key;
};

class ConfigStore {
public:
    static bool load(const std::string& path, AgentConfig& out);
    static bool save(const std::string& path, const AgentConfig& cfg);
};