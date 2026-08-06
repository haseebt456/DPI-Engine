#include "http_client.h"
#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace {

struct ParsedUrl {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port;
    bool secure;
};

std::wstring toWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring result(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], len);
    return result;
}

bool parseUrl(const std::string& url, ParsedUrl& out) {
    std::wstring wurl = toWide(url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostBuf[256] = {0};
    wchar_t pathBuf[2048] = {0};
    uc.lpszHostName = hostBuf;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = pathBuf;
    uc.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.size(), 0, &uc)) return false;
    out.host = hostBuf;
    out.path = pathBuf;
    out.port = uc.nPort;
    out.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

HttpResponse doRequest(const std::string& url, const std::wstring& method,
                       const std::string& body, const std::string& api_key) {
    HttpResponse result;
    ParsedUrl pu;
    if (!parseUrl(url, pu)) return result;

    HINTERNET hSession = WinHttpOpen(L"DPIAgent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;

    HINTERNET hConnect = WinHttpConnect(hSession, pu.host.c_str(), pu.port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return result; }

    DWORD flags = pu.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), pu.path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!api_key.empty()) headers += L"x-api-key: " + toWide(api_key) + L"\r\n";

    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.size(),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);

    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0, size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_FLAG_NUMBER | WINHTTP_QUERY_STATUS_CODE,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
        result.status_code = (int)statusCode;

        std::string responseBody;
        DWORD bytesAvailable = 0;
        do {
            bytesAvailable = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) break;
            if (bytesAvailable == 0) break;
            std::vector<char> buffer(bytesAvailable);
            DWORD bytesRead = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) break;
            responseBody.append(buffer.data(), bytesRead);
        } while (bytesAvailable > 0);

        result.body = responseBody;
        result.success = (statusCode >= 200 && statusCode < 300);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

} // namespace

HttpResponse HttpClient::get(const std::string& url, const std::string& api_key) {
    return doRequest(url, L"GET", "", api_key);
}

HttpResponse HttpClient::post(const std::string& url, const std::string& json_body, const std::string& api_key) {
    return doRequest(url, L"POST", json_body, api_key);
}