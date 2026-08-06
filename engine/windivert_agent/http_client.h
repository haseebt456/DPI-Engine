#pragma once
#include <string>

struct HttpResponse {
    int status_code = 0;
    std::string body;
    bool success = false;
};

class HttpClient {
public:
    static HttpResponse get(const std::string& url, const std::string& api_key = "");
    static HttpResponse post(const std::string& url, const std::string& json_body, const std::string& api_key = "");
};