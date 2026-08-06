#pragma once
#include <string>
#include <vector>
#include <utility>

struct RuleEntry {
    std::string type;
    std::string value;
};

// Minimal, purpose-built JSON helpers for this project's own API shapes --
// not a general-purpose parser. We control both ends (our own server), so
// this trades generality for zero external dependencies.
namespace JsonMini {
    std::vector<RuleEntry> parseRulesArray(const std::string& json);
    std::string escapeString(const std::string& s);
    std::string buildEnrollBody(const std::string& pairingCode);
    std::string buildEventsBody(const std::vector<std::pair<std::string, std::string>>& events);
    bool extractStringField(const std::string& json, const std::string& field, std::string& out);
}