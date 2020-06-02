#include "NetAsync.h"
#include <fstream>

#include <iostream>
using std::cout;
#pragma comment(lib, "WinINet.lib")

const wchar_t* const NetAsync::TEMP_FILE_SUFFIX = L".fileinfotemp";

NetAsync::NetAsync()
{
    init(DEFAULT_USER_AGENT, NetAsyncProxyType::System, nullptr, nullptr);
}

NetAsync::NetAsync(const wchar_t* userAgent, NetAsyncProxyType proxyType, const wchar_t* proxyServer, const wchar_t* proxyBypass)
{
    init(userAgent, proxyType, proxyServer, proxyBypass);
}
NetAsync::~NetAsync()
{
    if (hInternetRoot)
    {
        InternetSetStatusCallback(hInternetRoot, nullptr);
        InternetCloseHandle(hInternetRoot);
    }
}
bool NetAsync::startDownload(const wchar_t* url, const wchar_t* savePath, const NetCallbacks& callbacks)
{
    if (context.savedPath.length() != 0)
    {
        // this instance is in use
        return false;
    }
    context.savedPath = savePath;
    context.tempFilePath = context.savedPath + TEMP_FILE_SUFFIX;
    context.fileWriter.open(context.tempFilePath.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
    memcpy_s(&context.callbacks, sizeof(NetCallbacks), &callbacks, sizeof(NetCallbacks));
    InternetOpenUrlW(hInternetRoot, url, nullptr, 0, INTERNET_FLAG_NO_UI, (DWORD_PTR)& context);
    return true;
}
bool NetAsync::resumeDownload(const std::wstring& url, const std::wstring& savePath, DWORD dwNumberOfBytesAlreadyDownloaded, const NetCallbacks& callbacks)
{    
    if (context.savedPath.length() != 0)
    {
        // this instance is in use. Caller must delete old NetAsync object, and instantiate a new one
        return false;
    }
    //context.dwNumberOfByteDownloaded = dwNumberOfBytesAlreadyDownloaded;
    context.dwBytesDownloadedPreviously = dwNumberOfBytesAlreadyDownloaded;
    context.dwBytesDownloadedInThisSession = 0;
    context.isResumption = true;
    context.savedPath = savePath;
    context.tempFilePath = context.savedPath + L".fileinfotemp";
    context.fileWriter.open(context.tempFilePath.c_str(), std::ios::out | std::ios::app | std::ios::binary); // append to old file
    memcpy_s(&context.callbacks, sizeof(NetCallbacks), &callbacks, sizeof(NetCallbacks));

    std::wstring RangeHeader = L"Range: bytes=" + std::to_wstring(dwNumberOfBytesAlreadyDownloaded) + L"-\r\n";
    InternetOpenUrlW(hInternetRoot, url.c_str(), RangeHeader.c_str(), -1, INTERNET_FLAG_NO_UI, (DWORD_PTR)&context);
    return true;
}
void NetAsync::init(const wchar_t* userAgent, NetAsyncProxyType proxyType, const wchar_t* proxyServer, const wchar_t* proxyBypass)
{
    switch (proxyType)
    {
    case NetAsyncProxyType::Direct:
        hInternetRoot = InternetOpenW(userAgent, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, INTERNET_FLAG_ASYNC);
        break;
    case NetAsyncProxyType::System:
        hInternetRoot = InternetOpenW(userAgent, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, INTERNET_FLAG_ASYNC);
        break;
    case NetAsyncProxyType::UserSpecified:
        hInternetRoot = InternetOpenW(userAgent, INTERNET_OPEN_TYPE_PROXY, proxyServer, proxyBypass, INTERNET_FLAG_ASYNC);
        break;
    default:
        hInternetRoot = InternetOpenW(userAgent, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, INTERNET_FLAG_ASYNC);
        break;
    }

    if (hInternetRoot)
    {
        if (InternetSetStatusCallback(hInternetRoot, NetAsync::internalCallback) != INTERNET_INVALID_STATUS_CALLBACK)
        {
            isSuccess = true;
            dbgPrint(L"In init: InternetOpenW OK. InternetSetStatusCallback OK\n");
        }
    }
}
void __stdcall NetAsync::internalCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength)
{
    //dbgPrint(L"internal callback called.\n");
    auto context = (ContextStruct*)dwContext;
    switch (dwInternetStatus)
    {
    case INTERNET_STATUS_HANDLE_CREATED:
    {
        auto res = (INTERNET_ASYNC_RESULT*)lpvStatusInformation;
        if (res)
        {
            context->hInstance = (HINTERNET)(res->dwResult);
            dbgPrint(L"In internalCallback: Handle created\n");
        }
    }
    break;

    case INTERNET_STATUS_REQUEST_COMPLETE:
    {
        dbgPrint(L"Request complete\n");
        if (context->dwContentLength == -1)
        {
            DWORD dwBufLength = sizeof(DWORD);
            DWORD dwIndex = 0;
            if (!HttpQueryInfoW(context->hInstance, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_CONTENT_LENGTH, &context->dwContentLength, &dwBufLength, &dwIndex))
            {
                context->dwContentLength = NO_CONTENT_LENGTH;  // -2: error occurred; -1: not set yet; 0 - : actual Content-Length
            }
            dbgPrint(L"Content-Length: " + std::to_wstring(context->dwContentLength) + L"\n");
            if (context->callbacks.pContentLength)
                context->callbacks.pContentLength(context->dwContentLength);
        }
        if (context->dwStatusCode == -1)
        {
            DWORD dwBufLength = sizeof(DWORD);
            DWORD dwIndex = 0;
            if (!HttpQueryInfoW(context->hInstance, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &context->dwStatusCode, &dwBufLength, &dwIndex))
            {
                context->dwStatusCode = NO_STATUS_CODE;
            }
            if (context->dwStatusCode == NO_STATUS_CODE || (context->dwStatusCode >= 400 && context->dwStatusCode <= 599))
            {
                dbgPrint(L"Status code: " + std::to_wstring(context->dwStatusCode) + L"\n");
                InternetSetStatusCallbackW(context->hInstance, nullptr);
                InternetCloseHandle(context->hInstance);
                context->hInstance = nullptr;
                if (context->fileWriter.is_open())
                    context->fileWriter.close();
                DeleteFileW(context->tempFilePath.c_str());
                if (context->callbacks.pCompletion)
                    context->callbacks.pCompletion(false, context->dwStatusCode, 0, 0, context->savedPath);
                return;
            }
        }
        INTERNET_BUFFERSW ib;
        char buf[internalBufferLength];
        do
        {
            ZeroMemory(&ib, sizeof(INTERNET_BUFFERSW));
            ZeroMemory(buf, sizeof(buf));
            ib.dwStructSize = sizeof(INTERNET_BUFFERSW);
            ib.lpvBuffer = buf;
            ib.dwBufferLength = sizeof(buf);

            if (InternetReadFileExW(context->hInstance, &ib, IRF_ASYNC | IRF_NO_WAIT, dwContext))
            {
                dbgPrint(L"Received length: " + std::to_wstring(ib.dwBufferLength) + L"\n");
                if (ib.dwBufferLength == 0)
                {
                    InternetCloseHandle(context->hInstance);
                    context->hInstance = nullptr;
                    // HTTP response body has been downloaded completedly
                    if (context->dwContentLength == NO_CONTENT_LENGTH || context->dwContentLength == context->dwNumberOfByteDownloaded)
                    {
                        if (context->fileWriter.is_open())
                            context->fileWriter.close();
                        MoveFileW(context->tempFilePath.c_str(), context->savedPath.c_str());
                        //saveContentToDisk(context->vecContent, context->savedPath);
                        if (context->callbacks.pCompletion)
                            context->callbacks.pCompletion(true, context->dwStatusCode, context->dwNumberOfByteDownloaded, context->dwContentLength, context->savedPath);
                    }
                    else
                    {
                        // response is interrupted and truncated
                        if (context->fileWriter.is_open())
                            context->fileWriter.close();
                        //DeleteFileW(context->tempFilePath.c_str());    // keep temp file for resumption
                        if (context->callbacks.pCompletion)
                            context->callbacks.pCompletion(false, STATUS_NETASYNC_INTERRUPTED_RESPONSE, context->dwNumberOfByteDownloaded, context->dwContentLength, context->savedPath);
                    }
                    return;
                }
                else
                {
                    if (context->fileWriter.is_open())
                    {
                        context->fileWriter.write(buf, ib.dwBufferLength);
                    }
                    context->dwNumberOfByteDownloaded += ib.dwBufferLength;
                    if (context->callbacks.pProgress)
                        context->callbacks.pProgress(context->dwNumberOfByteDownloaded, context->dwContentLength);
                }
            }
            else
            {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING)
                {
                    break;
                }
                else
                {
                    // error occurred
                    break;
                }
            }
        } while (true);
    }
    break;
    default:
        //cout << "Code: " << dwInternetStatus << "\n";
        break;
    }
}

bool NetAsync::saveContentToDisk(const std::vector<char>& contentToSave, const std::wstring& path)
{
    std::ofstream writer(path.c_str(), std::ios::binary | std::ios::trunc);
    if (writer)
    {
        writer.write(contentToSave.data(), contentToSave.size());
        writer.close();
        return true;
    }
    else
    {
        return false;
    }
}

void NetAsync::dbgPrint(const std::wstring& msg)
{
    //wprintf(L"%s", msg.c_str());
}
