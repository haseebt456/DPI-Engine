#include "json_mini.h"
#include <sstream>

namespace {
std::string extractQuotedValue(const std::string& json, size_t keyPos) {
    size_t colon = json.find(':', keyPos);
    if (colon == std::string::npos) return "";
    size_t i = colon + 1;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) i++;
    if (i >= json.size() || json[i] != '"') return ""; // only handles string values
    size_t start = i + 1;
    size_t end = json.find('"', start);
    while (end != std::string::npos && end > 0 && json[end - 1] == '\\') {
        end = json.find('"', end + 1);
    }
    if (end == std::string::npos) return "";
    return json.substr(start, end - start);
}
}

bool JsonMini::extractStringField(const std::string& json, const std::string& field, std::string& out) {
    std::string key = "\"" + field + "\"";
    size_t pos = json.find(key);
    if (pos == std::string::npos) return false;
    out = extractQuotedValue(json, pos);
    return true;
}

std::vector<RuleEntry> JsonMini::parseRulesArray(const std::string& json) {
    std::vector<RuleEntry> result;
    size_t pos = 0;
    while (true) {
        size_t objStart = json.find('{', pos);
        if (objStart == std::string::npos) break;
        size_t objEnd = json.find('}', objStart);
        if (objEnd == std::string::npos) break;

        std::string obj = json.substr(objStart, objEnd - objStart + 1);
        std::string type, value;
        if (JsonMini::extractStringField(obj, "type", type) &&
            JsonMini::extractStringField(obj, "value", value)) {
            result.push_back({type, value});
        }
        pos = objEnd + 1;
    }
    return result;
}

std::string JsonMini::escapeString(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    return out;
}

std::string JsonMini::buildEnrollBody(const std::string& pairingCode) {
    return "{\"pairingCode\":\"" + escapeString(pairingCode) + "\"}";
}

std::string JsonMini::buildEventsBody(const std::vector<std::pair<std::string, std::string>>& events) {
    std::ostringstream oss;
    oss << "{\"events\":[";
    for (size_t i = 0; i < events.size(); i++) {
        if (i > 0) oss << ",";
        oss << "{\"domain\":\"" << escapeString(events[i].first)
            << "\",\"action\":\"" << escapeString(events[i].second) << "\"}";
    }
    oss << "]}";
    return oss.str();
}