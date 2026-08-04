#include "types.h"

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::HTTP:     return "HTTP";
        case AppType::HTTPS:    return "HTTPS";
        case AppType::YOUTUBE:  return "YouTube";
        case AppType::FACEBOOK: return "Facebook";
        case AppType::GOOGLE:   return "Google";
        case AppType::GITHUB:   return "GitHub";
        case AppType::TWITTER:  return "Twitter";
        case AppType::NETFLIX:  return "Netflix";
        default:                return "Unknown";
    }
}

// Very simple substring-based classifier. In a real system you'd use a
// proper domain-suffix trie, but substring matching is enough to demonstrate
// the concept and is easy to extend.
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube")  != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("google")   != std::string::npos) return AppType::GOOGLE;
    if (sni.find("github")   != std::string::npos) return AppType::GITHUB;
    if (sni.find("twitter")  != std::string::npos) return AppType::TWITTER;
    if (sni.find("netflix")  != std::string::npos) return AppType::NETFLIX;
    return AppType::HTTPS; // recognized as TLS, but not a named app
}
