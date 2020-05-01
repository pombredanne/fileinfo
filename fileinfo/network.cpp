#include "network.h"
#pragma comment(lib, "wininet.lib")
NetworkLib::NetworkLib()
{
    init(L"Downloader");
}
NetworkLib::NetworkLib(const wchar_t* userAgent)
{
    init(userAgent);
}
std::vector<char> NetworkLib::getURL(const wchar_t* url)
{
    std::vector<char> content;
    if (hInternet)
    {
        HINTERNET hFile = InternetOpenUrlW(hInternet, url, nullptr, 0, INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI, 0);
        if (hFile)
        {
            constexpr size_t buflen = 1024 * 1024;
            void* buf = malloc(buflen);  // 1MB
            DWORD lenRead = 0;
            if (buf)
            {
                BOOLEAN status = FALSE;
                while (true)
                {
                    status = InternetReadFile(hFile, buf, buflen, &lenRead);
                    if (status && lenRead > 0)
                    {
                        content.insert(content.end(), (char*)buf, (char*)buf + lenRead);
                    }
                    else
                    {
                        break;
                    }
                }
                free(buf);
            }
            InternetCloseHandle(hFile);
        }
        else
        {
            DWORD err = GetLastError();
            err;
        }
    }
    return content;
}
NetworkLib::~NetworkLib()
{
    if (hInternet)
        InternetCloseHandle(hInternet);
}
void NetworkLib::init(const wchar_t* userAgent)
{
    hInternet = InternetOpenW(userAgent, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
}
