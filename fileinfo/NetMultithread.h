#pragma once
#include "NetAsync.h"
#include <vector>
class NetMultithread
{
public:
    NetMultithread();
    NetMultithread(std::wstring userAgent);
    ~NetMultithread();

    bool startDownload();
private:
    const wchar_t* const DEFAULT_USER_AGENT = L"C++ Download Library";
    unsigned int numberOfParallelDownload = 5;
    const unsigned long chunkSize = 5 * 1024 * 1024;  // 5 MB

    std::vector<NetAsync*> vecDownloader;
    std::wstring userAgent;

    void init(std::wstring userAgent);
};
