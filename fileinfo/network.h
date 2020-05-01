#pragma once
#include <Windows.h>
#include <wininet.h>
#include <vector>
class NetworkLib
{
public:
    NetworkLib();
    NetworkLib(const wchar_t* userAgent);
    std::vector<char> getURL(const wchar_t* url);
    ~NetworkLib();

private:
    void init(const wchar_t* userAgent);
    HINTERNET hInternet;
};
