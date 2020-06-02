#pragma once
#include <Windows.h>
#include <WinInet.h>
#include <vector>
#include <string>
#include <fstream>

using CompletionCallback = void (*)(bool isSuccessful, DWORD statusCode, DWORD numberOfBytesRead, DWORD contentLength, std::wstring localSavedFilePath);
using ProgressCallback = void (*)(DWORD numberOfBytesRead, DWORD contentLength);
using ContentLengthCallback = void (*)(DWORD contentLength);
struct NetCallbacks
{
    CompletionCallback pCompletion;    // must delete the class instance here
    ProgressCallback pProgress;
    ContentLengthCallback pContentLength;
};
enum class NetAsyncProxyType
{
    Direct,
    System,
    UserSpecified
};

class NetAsync
{
public:
    NetAsync();
    NetAsync(const wchar_t* userAgent, NetAsyncProxyType proxyType, const wchar_t* proxyServer = nullptr, const wchar_t* proxyBypass = nullptr);
    ~NetAsync();

    bool startDownload(const wchar_t* url, const wchar_t* savePath, const NetCallbacks& callbacks);
    bool resumeDownload(const std::wstring& url, const std::wstring& savePath, DWORD dwNumberOfBytesAlreadyDownloaded, const NetCallbacks& callbacks);
    static constexpr DWORD NO_CONTENT_LENGTH = -2;
    static constexpr DWORD NO_STATUS_CODE = -2;
    static constexpr DWORD STATUS_NETASYNC_INTERRUPTED_RESPONSE = -3;
    static const wchar_t* const TEMP_FILE_SUFFIX;
private:
    const wchar_t* const DEFAULT_USER_AGENT = L"C++ Download Library";
    static constexpr size_t internalBufferLength = 2048;

    struct ContextStruct
    {
        HINTERNET hInstance = nullptr;
        DWORD dwContentLength = -1;  // -1: content-length not set, -2: error, other value: server's Content-Length value
        DWORD dwStatusCode = -1;
        //std::vector<char> vecContent;  // HTTP response in byte array
        DWORD dwNumberOfByteDownloaded = 0;
        DWORD dwBytesDownloadedPreviously = 0;  // used in resumption
        DWORD dwBytesDownloadedInThisSession = 0;  // used in resumption
        bool isResumption = false;
        std::wstring savedPath;
        std::wstring tempFilePath;
        NetCallbacks callbacks{};
        std::ofstream fileWriter;
    } context;

    HINTERNET hInternetRoot = nullptr;
    bool isSuccess = false;

    void init(const wchar_t* userAgent, NetAsyncProxyType proxyType, const wchar_t* proxyServer, const wchar_t* proxyBypass);
    static void __stdcall internalCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength);
    static bool saveContentToDisk(const std::vector<char>& contentToSave, const std::wstring& path);

    static void dbgPrint(const std::wstring& msg);
};
