#include <Windows.h>
#include <dbghelp.h>
#include <Shlwapi.h>
#include <Commctrl.h>  // for InitCommonControlsEx
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <tuple>
#include <fstream>
#include <uxtheme.h>  // for SetWindowTheme
#include <iostream>  // for testing
#include <io.h>  // for _open_osfhandle
#include <fcntl.h>  // for _O_APPEND
#include <algorithm>  // for std::remove
#include "crypto.h"
#include "NetAsync.h"

// add manifest to enable Comctl32 version2. Otherwise User32.dll controls are used.
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "UxTheme.lib")
using std::wstring;
using std::vector;
using std::ifstream;

// global variables
const wchar_t g_usage[] = LR"(This program displays information of Windows PE files.
Add this program to Windows Explorer right click menu for easy use, by setting these registry keys:
HKCR\dllfile\shell\Check Info\command: (default) [exe path] "%1" [option]
HKCR\exefile\shell\Check Info\command: (default) [exe path] "%1" [option]
HKCR\sysfile\shell\Check Info\command: (default) [exe path] "%1" [option]

Usage: QuickFileInfo.exe [file path] [--proxy=domain:port] [--dark | --light]
  --proxy: The proxy server to use to download PDB symbols from Microsoft.
           You can specify --proxy=direct to never use a proxy, and
           --proxy=system to use the system proxy.
  --dark | --light: Enable or disable dark mode. If not set, the system default theme is used.

Information shown by this program:
1. 64-bit vs 32-bit
2. Image characteristics
3. MD5, SHA1, SHA256
4. Debug GUID)";

const wchar_t g_MicrosoftSymbolServerURL[] = L"https://msdl.microsoft.com/download/symbols";
const wchar_t g_MozillaSymbolServerURL[] = L"https://symbols.mozilla.org/";
const wchar_t g_ChromiumSymbolServerURL[] = L"https://chromium-browser-symsrv.commondatastorage.googleapis.com";
const wchar_t g_Unity3dSymbolServerURL[] = L"https://symbolserver.unity3d.com/"; // Ref: https://docs.unity3d.com/Manual/WindowsDebugging.html
wstring g_symbolServerUsed = g_MicrosoftSymbolServerURL;
const wchar_t g_localSymbolCacheDirectory[] = L"C:\\ProgramData\\dbg\\sym";

struct undocCodeViewFormat
{
    // http://www.godevtool.com/Other/pdb.htm
    DWORD Signature;  // "RSDS"
    GUID guid;  // 16-byte GUID12
    DWORD age;  // incremented each time the executable and its associated pdb file is remade by the linker
    char pdbName[1];  // zero terminated UTF8 path and file name
};

wstring filePath;
wstring fileInfoMsg;
vector<char> g_fileContent;
bool is32bit = false;
DWORD numOfSection = 0;
std::vector<std::tuple<DWORD, DWORD, DWORD> > vecSectionInfo;  // <VA, PointerToRawData, VirtualSize>
IMAGE_OPTIONAL_HEADER32* pOptionalHeaders32 = nullptr;
IMAGE_OPTIONAL_HEADER64* pOptionalHeaders64 = nullptr;
// pointer to first section header
IMAGE_SECTION_HEADER* sectionHeader = nullptr;
DWORD debugDirectoryRva = 0;
DWORD debugDirectoryLen = 0;
wstring g_debugGUID;
wstring g_debugAge;
wstring g_pdbFile;
wstring g_exeKey;  // <TimeDateStamp><SizeOfImage> e.g. in `foo.exe/542d574232000/foo.exe`, 542d574232000 is g_exeKey
DWORD g_SizeOfImage;

HINSTANCE g_hInstance = nullptr;
HWND g_hMain = NULL;
HWND g_hEditMsg = NULL;
HWND g_hBtnDownloadSymbol = NULL;
HWND g_hBtnRegisterDLL = NULL;
HWND g_hBtnOpenProperties = NULL;
HWND g_hBtnConfig = NULL;
HWND g_hProgressBar = NULL;
HWND g_hEditStatus = NULL;
constexpr unsigned long MAIN_WIDTH = 650;
constexpr unsigned long MAIN_HEIGHT = 600;

NetAsync* fileDownloader = nullptr;
NetAsyncProxyType proxyType = NetAsyncProxyType::System;
wstring g_proxyServer;
bool g_isDarkMode = false;
bool g_forceDarkMode = false;  // true if dark mode is enabled in command line arguments
bool g_forceLightMode = false;  // true if light mode is enabled in command line arguments

#define COLOR_TOTAL_BLACK RGB(0,0,0)
#define COLOR_SOFT_WHITE RGB(200, 200, 200)
#define COLOR_TOTAL_WHITE RGB(255, 255, 255)

// prototypes
bool doWork();
void showUsage();
bool extractBasicInfo();
void extractSectionInfo();
void extractDebugGUID(IMAGE_DEBUG_DIRECTORY* pFirstDebugDirectory);
void showInfo(const std::wstring& msg);
bool readByteWithRange(const std::wstring& filePath, const size_t start, size_t len = -1);
void parseSubsystem(WORD Subsystem);
void parseDllCharacteristics(WORD dll);
DWORD rvaToRaw(DWORD rva);
wstring guidToWstring(const GUID& guid);
void getHashMessage(const char* const fileContent, const unsigned long fileLen);
bool downloadSymbolToDisk(const wstring& symbolServer, const wstring& symbolGUID, const wstring& symbolAge, const wstring& symbolFilename, const wstring& localSymbolPath);
void HandleControlCommands(UINT code, HWND hwnd);
bool appendTextOnEdit(HWND hEdit, const std::wstring& str);
bool getFileSizeFromPath(const wstring& filePath, DWORD& filesize);
bool createDirectoryTreeForSpecifiedFile(const wstring& fileFullPath);
void writeConsole(HANDLE hConsoleOutput, const std::wstring& str);
wstring getStdin(HANDLE hConsoleInput, bool trimNewLine = true);
void setDarkModeBasedOnSystemTheme();

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        INITCOMMONCONTROLSEX st{ sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES };
        if (InitCommonControlsEx(&st))
        {
            g_hEditMsg = CreateWindowExW(0, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                0, 0, 10, 10, hwnd, NULL, g_hInstance, nullptr);
            
            appendTextOnEdit(g_hEditMsg, fileInfoMsg);
            SendMessageW(g_hEditMsg, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 10);

            g_hBtnDownloadSymbol = CreateWindowExW(WS_EX_CLIENTEDGE, L"BUTTON", L"Download Symbol",
                WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | (g_isDarkMode ? BS_OWNERDRAW : 0), 0, 0, 10, 10, hwnd, NULL, g_hInstance, nullptr);
            if ((g_debugGUID.size() == 0) || (g_pdbFile.size() == 0))
            {
                EnableWindow(g_hBtnDownloadSymbol, FALSE);
            }

            g_hBtnRegisterDLL = CreateWindowExW(WS_EX_CLIENTEDGE, L"BUTTON", L"Register DLL",
                WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | (g_isDarkMode ? BS_OWNERDRAW : 0), 0, 0, 10, 10, hwnd, NULL, g_hInstance, nullptr);

            g_hBtnOpenProperties = CreateWindowExW(WS_EX_CLIENTEDGE, L"BUTTON", L"Properties",
                WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | (g_isDarkMode ? BS_OWNERDRAW : 0), 0, 0, 10, 10, hwnd, NULL, g_hInstance, nullptr);

            g_hBtnConfig = CreateWindowExW(WS_EX_CLIENTEDGE, L"BUTTON", L"Configure",
                WS_TABSTOP | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | (g_isDarkMode ? BS_OWNERDRAW : 0), 0, 0, 10, 10, hwnd, NULL, g_hInstance, nullptr);

            g_hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE, 0,
                0, 10, 10, hwnd, NULL, g_hInstance, nullptr);
            if (g_isDarkMode)
            {
                SetWindowTheme(g_hProgressBar, L" ", L" ");
                SendMessageW(g_hProgressBar, PBM_SETBARCOLOR, 0, RGB(38, 79, 120));  // dark blue
                SendMessageW(g_hProgressBar, PBM_SETBKCOLOR, 0, RGB(0, 0, 0));  // black
            }
            g_hEditStatus = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | ES_READONLY,
                0, 0, 10, 10, hwnd, NULL, g_hInstance, nullptr);

            // set font
            HFONT hFont = CreateFontA(-17, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Times New Roman");
            HWND arr_hwndNeedFont[] = { g_hEditMsg, g_hBtnDownloadSymbol, g_hBtnRegisterDLL, g_hBtnOpenProperties, g_hBtnConfig, g_hEditStatus };
            for (size_t i = 0; i < _countof(arr_hwndNeedFont); i++)
            {
                SendMessageW(arr_hwndNeedFont[i], WM_SETFONT, (WPARAM)hFont, MAKELPARAM(FALSE, 0));
            }
        }
        break;
    }
    case WM_SIZE:
    {
        RECT rcClient;
        GetClientRect(hwnd, &rcClient);
        if (g_hEditMsg)
            SetWindowPos(g_hEditMsg, NULL, 0, 5, rcClient.right, rcClient.bottom - 110, SWP_NOZORDER);
        HWND arr_hwndBtn[] = { g_hBtnDownloadSymbol, g_hBtnRegisterDLL, g_hBtnOpenProperties, g_hBtnConfig };
        for (int i = 0; i < _countof(arr_hwndBtn); i++)
        {
            if (arr_hwndBtn[i])
            {
                SetWindowPos(arr_hwndBtn[i], NULL, (long long)rcClient.right * i / _countof(arr_hwndBtn), rcClient.bottom - 100,
                    rcClient.right / _countof(arr_hwndBtn), 50, SWP_NOZORDER);
            }
        }
        if (g_hProgressBar)
        {
            SetWindowPos(g_hProgressBar, NULL, 10, rcClient.bottom - 40, (rcClient.right - 20) / 2, 30, SWP_NOZORDER);
        }
        if (g_hEditStatus)
            SetWindowPos(g_hEditStatus, NULL, rcClient.right / 2 + 5, rcClient.bottom - 40, (rcClient.right - 20) / 2, 30, SWP_NOZORDER);
        break;
    }
    case WM_DRAWITEM:
    {
        // Sent by owner-drawn buttons
        // wParam: identifier of the control
        // lParam: pointer to a DRAWITEMSTRUCT
        LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
        wchar_t textBuffer[100]{};
        int len = static_cast<int>(SendMessageW(pDIS->hwndItem, WM_GETTEXT, ARRAYSIZE(textBuffer), (LPARAM)textBuffer));
        DrawTextW(pDIS->hDC, textBuffer, -1, &pDIS->rcItem, DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        return TRUE;
    }
    case WM_CTLCOLORBTN:
    {
        // wParam: HDC
        // lParam: handle to button
        HDC hdcBtn = (HDC)wParam;
        if (g_isDarkMode)
        {
            SetTextColor(hdcBtn, COLOR_SOFT_WHITE);
            SetBkColor(hdcBtn, COLOR_TOTAL_BLACK);
            SetDCBrushColor(hdcBtn, COLOR_TOTAL_BLACK);
        }
        else
        {
            SetTextColor(hdcBtn, COLOR_TOTAL_BLACK);
            SetBkColor(hdcBtn, COLOR_TOTAL_WHITE);
            SetDCBrushColor(hdcBtn, COLOR_TOTAL_WHITE);
        }
        return (LRESULT)GetStockObject(DC_BRUSH);
    }
    case WM_CTLCOLORSTATIC:
    {
        // Sent by a static control, or a read-only or disabled edit control
        // wParam: HDC
        // lParam: handle to button
        HDC hdcStatic = (HDC)wParam;
        if (g_isDarkMode)
        {
            SetTextColor(hdcStatic, COLOR_SOFT_WHITE);
            SetBkColor(hdcStatic, COLOR_TOTAL_BLACK);
            SetDCBrushColor(hdcStatic, COLOR_TOTAL_BLACK);
        }
        else
        {
            SetTextColor(hdcStatic, COLOR_TOTAL_BLACK);
            SetBkColor(hdcStatic, COLOR_TOTAL_WHITE);
            SetDCBrushColor(hdcStatic, COLOR_TOTAL_WHITE);
        }
        return (LRESULT)GetStockObject(DC_BRUSH);
    }        
    case WM_COMMAND:
        HandleControlCommands(HIWORD(wParam), (HWND)lParam);
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv || !argc)
    {
        return 1;
    }

    if (argc == 1)
    {
        showUsage();
        return 0;
    }
    else
    {
        std::wstring arg1 = argv[1];
        if (arg1 == L"/?" || arg1 == L"--help" || arg1 == L"-h" || arg1 == L"-?")
        {
            showUsage();
            return 0;
        }
        filePath = arg1;
        if (argc >= 3)
        {
            for (int index = 2; index < argc; index++)
            {
                std::wstring arg = argv[index];
                if (arg.find(L"--proxy=") == 0 && arg.length() > 8)
                {
                    arg = arg.substr(8);
                    if (arg == L"direct")
                    {
                        proxyType = NetAsyncProxyType::Direct;
                    }
                    else if (arg == L"system")
                    {
                        proxyType = NetAsyncProxyType::System;
                    }
                    else
                    {
                        proxyType = NetAsyncProxyType::UserSpecified;
                        g_proxyServer = arg;
                    }
                }
                else if (arg.find(L"--dark") == 0)
                {
                    g_forceDarkMode = true;
                }
                else if (arg.find(L"--light") == 0)
                {
                    g_forceLightMode = true;
                }
            }
            
        }
        if (!doWork())
        {
            return 0;
        }
    }
    setDarkModeBasedOnSystemTheme();

    g_hInstance = hInstance;
    const static wchar_t* swMainClassName = L"main";
    WNDCLASSEXW wc{ sizeof(WNDCLASSEXW), 0, WndProc, 0, 0, hInstance, LoadIconA(nullptr, IDI_APPLICATION),
        LoadCursorA(nullptr, IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), nullptr, swMainClassName, LoadIconA(nullptr, IDI_APPLICATION) };

    if (g_isDarkMode)
    {
        wc.hbrBackground = CreateSolidBrush(COLOR_TOTAL_BLACK);
    }
    else
    {
        wc.hbrBackground = CreateSolidBrush(COLOR_TOTAL_WHITE);
    }
    MSG Msg;
    if (!RegisterClassExW(&wc))
    {
        MessageBoxW(NULL, L"Error: Can't register class", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }
    g_hMain = CreateWindowExW(WS_EX_CLIENTEDGE, swMainClassName, L"Quick File Info", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, MAIN_WIDTH, MAIN_HEIGHT, NULL, NULL, hInstance, NULL);
    if (!g_hMain)
    {
        MessageBoxW(NULL, L"Error: Can't create window", L"Error", MB_ICONERROR | MB_OK);
        return 2;
    }
    ShowWindow(g_hMain, nShowCmd);
    UpdateWindow(g_hMain);
    while (GetMessageW(&Msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&Msg);
        DispatchMessageW(&Msg);
    }
    return static_cast<int>(Msg.wParam);
}
/*int main(void)
{
    if (downloadSymbolToDisk(L"https://msdl.microsoft.com/download/symbols", L"A3028D6B45DA006244A6C9E4DDDA11021", L"rpcrt4.pdb",
        L"C:\\ProgramData\\dbg\\sym"))
        std::cout << "OK\n";
    else
        std::cout << "Not OK\n";
    std::cout << "Done\n";
    getchar();
    return 0;
}*/
bool doWork()
{
    bool status = false;
    status = readByteWithRange(filePath, 0, -1);
    if (!status)
    {
        showInfo(L"Error: " + filePath + L" can't be opened.");
        return false;
    }
    if (g_fileContent.size() < 1024)
    {
        showInfo(L"Error: " + filePath + L" is not a valid PE file. File is too small.");
        return false;
    }
    fileInfoMsg += L"File: " + filePath + L"\r\n";
    if (!extractBasicInfo())
    {
        return false;
    }
    //status = readByteWithRange(filePath, 0, -1);
    if (!status)
    {
        showInfo(L"Error: " + filePath + L" can't be opened.");
        return false;
    }
    extractSectionInfo();
    DWORD debugDirectoryRaw = rvaToRaw(debugDirectoryRva);
    void* pDebug = g_fileContent.data() + debugDirectoryRaw;
    extractDebugGUID(static_cast<IMAGE_DEBUG_DIRECTORY*>(pDebug));
    fileInfoMsg += L"\r\n";
    getHashMessage(g_fileContent.data(), static_cast<unsigned long>(g_fileContent.size()));
    return true;
}
void showUsage()
{
    showInfo(g_usage);
}
void showInfo(const std::wstring& msg)
{
    MessageBoxW(g_hMain ? g_hMain : nullptr, msg.c_str(), L"Quick File Information", MB_OK);
}
bool readByteWithRange(const std::wstring& filePath, const size_t start, size_t len)
{
    // if len == -1, read to end
    // read to global variable g_fileContent
    ifstream reader(filePath.c_str(), std::ios::binary);
    if (!reader)
    {
        g_fileContent.resize(0);
        return false;
    }
    
    if (len == -1)
    {
        // get total len:
        reader.seekg(0, std::ios::end);
        size_t total_len = reader.tellg();
        if (start >= total_len || total_len == 0)
        {
            g_fileContent.resize(0);
            return false;
        }
        reader.seekg(start, std::ios::beg);
        len = total_len - start;
        g_fileContent.resize(len);
        reader.read(g_fileContent.data(), len);
    }
    else
    {
        reader.seekg(start, std::ios::beg);
        if (reader.eof())
        {
            g_fileContent.resize(0);
            return false;
        }
        g_fileContent.resize(len);
        reader.read(g_fileContent.data(), len);
        if (reader.eof())
        {
            g_fileContent.resize(0);
            return false;
        }
    }
    return true;
}
bool extractBasicInfo()
{
    void* fileCurrentParsePosition = g_fileContent.data();
    IMAGE_DOS_HEADER* dosHeader = static_cast<IMAGE_DOS_HEADER*>(fileCurrentParsePosition);
    if (dosHeader->e_magic != 'ZM')
    {
        showInfo(L"Error: File " + filePath + L" is not a valid PE file: does not start with \"PE\"");
        return false;
    }
    LONG offsetToNtHeader = dosHeader->e_lfanew;
    if (offsetToNtHeader + sizeof(IMAGE_NT_HEADERS32) > g_fileContent.size() ||
        offsetToNtHeader + sizeof(IMAGE_NT_HEADERS64) > g_fileContent.size())
    {
        showInfo(L"Error: File " + filePath + L" is not a valid PE file: DOS header's e_lfanew value is too large");
        return false;
    }
    fileCurrentParsePosition = g_fileContent.data() + offsetToNtHeader;
    auto nt32Header = static_cast<IMAGE_NT_HEADERS32*>(fileCurrentParsePosition);
    if (nt32Header->Signature != 'EP')
    {
        // wrong signature
        showInfo(L"Error: File " + filePath + L" is not a valid PE file: Wrong PE Signature");
        return false;
    }
    const auto& fileHeader = nt32Header->FileHeader;
    switch (fileHeader.Machine)
    {
    case IMAGE_FILE_MACHINE_I386:
        fileInfoMsg += L"Architecture: 32-bit x86\r\n";
        break;
    case IMAGE_FILE_MACHINE_IA64:
        fileInfoMsg += L"Architecture: IA64\r\n";
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        fileInfoMsg += L"Architecture: 64-bit x64\r\n";
        break;
    case IMAGE_FILE_MACHINE_ARM:
        fileInfoMsg += L"Architecture: ARM\r\n";
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        fileInfoMsg += L"Architecture: ARM64\r\n";
        break;
    default:
        fileInfoMsg += L"Architecture: Unknown\r\n";
        break;
    }
    fileInfoMsg += L"Number of sections: " + std::to_wstring(fileHeader.NumberOfSections) + L"\r\n";
    numOfSection = fileHeader.NumberOfSections;

    WORD characteristics = fileHeader.Characteristics;

#define CHECK_AND_OUTPUT_CHARACTERISTIC(name) do { \
fileInfoMsg = fileInfoMsg + L#name + L": " + ((characteristics & name) ? L"Yes" : L"No") + L"\r\n";\
} while(0)

    CHECK_AND_OUTPUT_CHARACTERISTIC(IMAGE_FILE_RELOCS_STRIPPED);
    CHECK_AND_OUTPUT_CHARACTERISTIC(IMAGE_FILE_EXECUTABLE_IMAGE);
    CHECK_AND_OUTPUT_CHARACTERISTIC(IMAGE_FILE_LARGE_ADDRESS_AWARE);
    CHECK_AND_OUTPUT_CHARACTERISTIC(IMAGE_FILE_32BIT_MACHINE);
    CHECK_AND_OUTPUT_CHARACTERISTIC(IMAGE_FILE_SYSTEM);
    CHECK_AND_OUTPUT_CHARACTERISTIC(IMAGE_FILE_DLL);
#undef CHECK_AND_OUTPUT_CHARACTERISTIC

    if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        const auto& optionalHeader = nt32Header->OptionalHeader;
        if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            showInfo(L"Error: File " + filePath + L" is not a valid PE file: OptionalHeader32.Magic is incorrect.");
            return false;
        }
        g_SizeOfImage = optionalHeader.SizeOfImage;
        is32bit = true;
        pOptionalHeaders32 = &nt32Header->OptionalHeader;
        sectionHeader = (IMAGE_SECTION_HEADER*)(nt32Header + 1);
        debugDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        debugDirectoryLen = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;  // debug directory
        if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0)
        {
            fileInfoMsg += L".NET executable: Yes\r\n";
        }
        else
        {
            fileInfoMsg += L".NET executable: No\r\n";
        }
        
        parseSubsystem(pOptionalHeaders32->Subsystem);
        parseDllCharacteristics(pOptionalHeaders32->DllCharacteristics);
    }
    else if (fileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        auto nt64Header = static_cast<IMAGE_NT_HEADERS64*>(fileCurrentParsePosition);
        const auto& optionalHeader = nt64Header->OptionalHeader;
        if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            showInfo(L"Error: File " + filePath + L" is not a valid PE file: OptionalHeader64.Magic is incorrect.");
            return false;
        }
        g_SizeOfImage = optionalHeader.SizeOfImage;
        is32bit = false;
        pOptionalHeaders64 = &nt64Header->OptionalHeader;
        sectionHeader = (IMAGE_SECTION_HEADER*)(nt64Header + 1);
        debugDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        debugDirectoryLen = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;  // debug directory
        if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0)
        {
            fileInfoMsg += L".NET executable: Yes\r\n";
        }
        else
        {
            fileInfoMsg += L".NET executable: No\r\n";
        }

        parseSubsystem(pOptionalHeaders64->Subsystem);
        parseDllCharacteristics(pOptionalHeaders64->DllCharacteristics);
    }
    else
    {
        showInfo(L"Error: File " + filePath + L" is not a valid PE file: size of optional header is incorrect");
        return false;
    }
    return true;
}
void parseSubsystem(WORD Subsystem)
{
    switch (Subsystem) {        
    case IMAGE_SUBSYSTEM_NATIVE: fileInfoMsg += L"Subsystem: driver or native exe\r\n"; break; 
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: fileInfoMsg += L"Subsystem: GUI\r\n"; break; 
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: fileInfoMsg += L"Subsystem: Console\r\n"; break; 
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: fileInfoMsg += L"Subsystem: Boot application\r\n"; break; 
    default: fileInfoMsg += L"Subsystem: Unknown (" + std::to_wstring(Subsystem) + L")\r\n"; break;
    }
}
void parseDllCharacteristics(WORD dll)
{
    fileInfoMsg += L"DLL Characteristics:\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
        fileInfoMsg += L"  High entropy 64-bit address space\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        fileInfoMsg += L"  The DLL can be relocated at load time.\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        fileInfoMsg += L"  Code integrity checks are forced (linker: /integritycheck).\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        fileInfoMsg += L"  DEP enabled\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)
        fileInfoMsg += L"  The image is isolation aware, but should not be isolated.\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_NO_SEH)
        fileInfoMsg += L"  No SEH\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_NO_BIND)
        fileInfoMsg += L"  Do not bind this image.\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)
        fileInfoMsg += L"  WDM driver\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
        fileInfoMsg += L"  Terminal server aware\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        fileInfoMsg += L"  CFG enabled\r\n";
    if (dll & IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
        fileInfoMsg += L"  Should run in AppContainer\r\n";
}
void extractSectionInfo()
{
    if (!sectionHeader || !numOfSection)
        return;
    
    for (DWORD index = 0; index < numOfSection; index++)
    {
        IMAGE_SECTION_HEADER* currentSectionHeader = sectionHeader + index;
        DWORD va = currentSectionHeader->VirtualAddress;
        DWORD virtualsize = currentSectionHeader->Misc.VirtualSize;
        DWORD ptrToRawData = currentSectionHeader->PointerToRawData;

        // <VA, PointerToRawData, Size>
        vecSectionInfo.push_back(std::make_tuple(va, ptrToRawData, virtualsize));        
    }
    fileInfoMsg += L"\r\n";
}
void extractDebugGUID(IMAGE_DEBUG_DIRECTORY* pFirstDebugDirectory)
{
    // https://github.com/dotnet/symstore/blob/master/docs/specs/SSQP_Key_Conventions.md
    if (debugDirectoryLen % sizeof(IMAGE_DEBUG_DIRECTORY) != 0)
        return;
    size_t numOfDebugDirectory = debugDirectoryLen / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (size_t i = 0; i < numOfDebugDirectory; i++)
    {
        auto curDebugDir = pFirstDebugDirectory + i;
        if (curDebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            DWORD dataLen = curDebugDir->SizeOfData;
            DWORD dataRva = curDebugDir->AddressOfRawData;
            DWORD dataRaw = curDebugDir->PointerToRawData;
            DWORD dataCalculatedRaw = rvaToRaw(dataRva);
            if (dataCalculatedRaw == dataRaw)
            {
                // info is consistent
                auto rsdsStruct = static_cast<undocCodeViewFormat*>(static_cast<void*>(g_fileContent.data() + dataRaw));
                wstring wGUID = guidToWstring(rsdsStruct->guid);
                std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                std::wstring wPDbFileName = converter.from_bytes(rsdsStruct->pdbName);
                fileInfoMsg += L"PDB GUID: " + wGUID + L"\r\n";
                fileInfoMsg += L"PDB File: " + wPDbFileName + L"\r\n";

                g_debugAge = std::to_wstring(rsdsStruct->age);
                g_debugGUID = wGUID;
                g_pdbFile = wPDbFileName;
                DWORD timestamp = curDebugDir->TimeDateStamp;
                wchar_t exekey[17]{};
                swprintf_s(exekey, L"%08X%X", timestamp, g_SizeOfImage);  // timestamp (but not size of image) must pad to 8 chars with zeros prefixed
                g_exeKey = exekey;
            }
        }
    }
}
DWORD rvaToRaw(DWORD rva)
{
    for (const auto& sec : vecSectionInfo)
    {
        DWORD va = 0;
        DWORD vSize = 0;
        DWORD ptrToRawData = 0;
        std::tie(va, ptrToRawData, vSize) = sec;
        if (rva >= va && rva < va + vSize)
        {
            return rva - va + ptrToRawData;
        }
    }
    return 0;
}
wstring guidToWstring(const GUID& guid)
{
    wchar_t wsGUID[100]{};
    if (StringFromGUID2(guid, wsGUID, sizeof(wsGUID) / sizeof(wsGUID[0])) > 0)
    {
        return wstring(wsGUID);
    }
    return L"";
}
void getHashMessage(const char* const fileContent, const unsigned long fileLen)
{
    std::wstring wsMD5 = GetHashText(fileContent, fileLen, HashType::HashMd5);
    std::wstring wsSHA1 = GetHashText(fileContent, fileLen, HashType::HashSha1);
    std::wstring wsSHA256 = GetHashText(fileContent, fileLen, HashType::HashSha256);
    if (wsMD5.length() > 0)
        fileInfoMsg += L"MD5: " + wsMD5 + L"\r\n";
    if (wsSHA1.length() > 0)
        fileInfoMsg += L"SHA1: " + wsSHA1 + L"\r\n";
    if (wsSHA256.length() > 0)
        fileInfoMsg += L"SHA256: " + wsSHA256 + L"\r\n";
}
void pdbDownloadCompleted(bool successful, DWORD dwStatusCode, DWORD numberOfBytesRead, DWORD contentLength)
{
    delete fileDownloader;
    fileDownloader = nullptr;
    if (successful)
    {
        SendMessageW(g_hProgressBar, PBM_SETPOS, 1000, 0);
        SendMessageW(g_hProgressBar, PBM_SETBARCOLOR, 0, COLOR_TOTAL_BLACK);
        SetWindowTextW(g_hEditStatus, (L"Succeeded. Size=" + std::to_wstring(numberOfBytesRead) + L" bytes").c_str());
    }
    else
    {
        SendMessageW(g_hProgressBar, PBM_SETPOS, 0, 0);
        switch (dwStatusCode)
        {
        case NetAsync::NO_STATUS_CODE:
            SetWindowTextW(g_hEditStatus, L"Error: Connection failed");
            break;
        case NetAsync::STATUS_NETASYNC_INTERRUPTED_RESPONSE:
            SetWindowTextW(g_hEditStatus, L"Error: Download interrupted");            
            break;
        default:
            SetWindowTextW(g_hEditStatus, (L"Error: " + std::to_wstring(dwStatusCode)).c_str());
            break;
        }
    }
    EnableWindow(g_hBtnDownloadSymbol, TRUE);
    EnableWindow(g_hBtnConfig, TRUE);
}
void pdbDownloadProgressNotified(DWORD numberOfBytesRead, DWORD contentLength)
{
    if (contentLength == NetAsync::NO_CONTENT_LENGTH)
    {
        SetWindowTextW(g_hEditStatus, (std::to_wstring(numberOfBytesRead) + L" bytes downloaded").c_str());
        return;
    }
    if (numberOfBytesRead <= contentLength)
    {
        unsigned long long temp = numberOfBytesRead;  // avoid overflow
        temp *= 1000;
        temp /= contentLength;
        DWORD percentage = static_cast<DWORD>(temp);
        SendMessageW(g_hProgressBar, PBM_SETPOS, percentage, 0);
        SetWindowTextW(g_hEditStatus, (std::to_wstring(numberOfBytesRead) + L" / " + std::to_wstring(contentLength) + L" bytes").c_str());
    }
}
void pdbDownloadContentLengthObtained(DWORD contentLength)
{
    SendMessageW(g_hProgressBar, PBM_SETRANGE32, 0, 1000);
    if (contentLength != NetAsync::NO_CONTENT_LENGTH)
    {
        SetWindowTextW(g_hEditStatus, (L"0 bytes / " + std::to_wstring(contentLength)).c_str());
    }        
    else
    {
        SetWindowTextW(g_hEditStatus, L"0 bytes downloaded");
    }
}
void copyModuleBinaryToDisk(const wstring& binaryFilePath, const wstring& exekey, const wstring& localSymbolPath)
{
    wstring filenamepart;
    size_t lastBackslashInFilename = binaryFilePath.find_last_of(L'\\');
    filenamepart = binaryFilePath.substr(lastBackslashInFilename + 1);
    if (filenamepart.length() == 0)
        return;  // should not happen
    wstring fullCachePath = localSymbolPath + L"\\" + filenamepart + L"\\" + exekey + L"\\" + filenamepart;
    if (PathFileExistsW(fullCachePath.c_str()))
    {
        appendTextOnEdit(g_hEditMsg, L"Binary file is already cached at " + fullCachePath + L"\r\n");
    }
    else
    {
        createDirectoryTreeForSpecifiedFile(fullCachePath);
        if (CopyFileW(binaryFilePath.c_str(), fullCachePath.c_str(), TRUE))
        {
            appendTextOnEdit(g_hEditMsg, L"Binary file has been cached to " + fullCachePath + L"\r\n");
        }
        else
        {
            DWORD err = GetLastError();
            wstring errMsg;
            switch (err)
            {
            case ERROR_ACCESS_DENIED:
                errMsg = L"Access denied";
                break;
            default:
                errMsg = L"Error " + std::to_wstring(err);
                break;
            }
            appendTextOnEdit(g_hEditMsg, L"Error: Cannot copy binary file to " + fullCachePath + L": " + errMsg + L"\r\n");
        }
    }
}
bool downloadSymbolToDisk(const wstring& symbolServer, const wstring& symbolGUID, const wstring& symbolAge, const wstring& symbolFilename, const wstring& localSymbolPath)
{
    if (symbolGUID.length() == 0 || symbolFilename.length() == 0)
        return false;
    // e.g. https://msdl.microsoft.com/download/symbols/rpcrt4.pdb/A3028D6B45DA006244A6C9E4DDDA11021/rpcrt4.pdb
    wstring urlToDownload;
    wstring normalizedSymbolGUID;
    wstring normalizedSymbolFilename;  // extract filename in case symbolFilename is full path
    size_t lastBackslashInFilename = symbolFilename.find_last_of(L"/\\");    
    if (lastBackslashInFilename != -1)
    {
        normalizedSymbolFilename = symbolFilename.substr(lastBackslashInFilename + 1);
    }
    else
    {
        normalizedSymbolFilename = symbolFilename;
    }
    if (normalizedSymbolFilename.length() == 0)
        return false;
    for (const auto k : symbolGUID)
    {
        if ((k >= L'A' && k <= L'Z') || (k >= L'0' && k <= L'9'))
        {
            normalizedSymbolGUID += k;
        }
        else if (k >= L'a' && k <= L'z')
        {
            normalizedSymbolGUID += ( k - (L'a' - L'A'));
        }
    }
    normalizedSymbolGUID += symbolAge;
    if (symbolServer.find_last_of(L'/') == symbolServer.length() - 1)
    {
        urlToDownload = symbolServer + normalizedSymbolFilename + L"/" + normalizedSymbolGUID + L"/" + normalizedSymbolFilename;
    }
    else
    {
        urlToDownload = symbolServer + L"/" + normalizedSymbolFilename + L"/" + normalizedSymbolGUID + L"/" + normalizedSymbolFilename;
    }   
    
    wstring dirToCreate;
    if (localSymbolPath.find_last_of(L'\\') == localSymbolPath.length() - 1)
    {
        dirToCreate = localSymbolPath + normalizedSymbolFilename;
    }
    else
    {
        dirToCreate = localSymbolPath + L'\\' + normalizedSymbolFilename;
    }
    CreateDirectoryW(dirToCreate.c_str(), nullptr);
    dirToCreate += L'\\' + normalizedSymbolGUID;
    CreateDirectoryW(dirToCreate.c_str(), nullptr);
    wstring pdbPath = dirToCreate + L"\\" + normalizedSymbolFilename;
    if (PathFileExistsW(pdbPath.c_str()))
    {
        appendTextOnEdit(g_hEditMsg, L"PDB file is already cached at " + pdbPath + L"\r\n");
        return true;
    }
    if (fileDownloader)
    {
        // another download is in progress. We should not start a new download.
        return false;
    }

    wstring pdbTempPath = pdbPath + NetAsync::TEMP_FILE_SUFFIX;
    bool isResume = false;
    DWORD bytesAlreadyDownloaded = 0;
    if (PathFileExistsW(pdbTempPath.c_str()))
    {
        isResume = true;
        if (!getFileSizeFromPath(pdbTempPath, bytesAlreadyDownloaded))
        {
            // This shouldn't happen
            return false;
        }
        appendTextOnEdit(g_hEditMsg, L"Resuming PDB download from " + urlToDownload + L"\r\n");
    }
    else
    {
        appendTextOnEdit(g_hEditMsg, L"Downloading PDB from " + urlToDownload + L"\r\n");
    }    

    fileDownloader = new NetAsync(L"PDB Symbol Downloader", proxyType, g_proxyServer.c_str(), L"<local>");
    NetCallbacks callbacks{ };
    callbacks.pCompletion = pdbDownloadCompleted;
    callbacks.pContentLength = pdbDownloadContentLengthObtained;
    callbacks.pProgress = pdbDownloadProgressNotified;

    bool isSuccess = false;
    if (isResume)
    {
        isSuccess = fileDownloader->resumeDownload(urlToDownload, pdbPath, bytesAlreadyDownloaded, callbacks);
    }
    else
    {
        isSuccess = fileDownloader->startDownload(urlToDownload.c_str(), pdbPath.c_str(), callbacks);
    }
    return isSuccess;
    /*
    NetworkLib downloader(L"PDB Symbol Downloader");
    vector<char> pdbContent = downloader.getURL(urlToDownload.c_str());
    if (pdbContent.size() == 0)
    {
        return false;
    }
    std::ofstream writer(pdbPath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    if (writer)
    {
        writer.write(pdbContent.data(), pdbContent.size());
        writer.close();
        return true;
    }
    return false;*/
}
bool appendTextOnEdit(HWND hEdit, const std::wstring& str)
{
    int index = GetWindowTextLengthW(hEdit);
    SendMessageW(hEdit, EM_SETSEL, (WPARAM)index, (LPARAM)index);
    SendMessageW(hEdit, EM_REPLACESEL, NULL, (LPARAM)str.c_str());
    return true;
}
void HandleControlCommands(UINT code, HWND hwnd)
{
    if (!hwnd) return;  // not Control
    if (code == BN_CLICKED)
    {
        if (hwnd == g_hBtnDownloadSymbol)
        {
            SetWindowTextW(g_hEditStatus, L"");
            EnableWindow(g_hBtnDownloadSymbol, FALSE);
            EnableWindow(g_hBtnConfig, FALSE);
            appendTextOnEdit(g_hEditMsg, L"\r\n");
            copyModuleBinaryToDisk(filePath, g_exeKey, g_localSymbolCacheDirectory);
            if (downloadSymbolToDisk(g_symbolServerUsed, g_debugGUID, g_debugAge, g_pdbFile, g_localSymbolCacheDirectory))
            {
                //appendTextOnEdit(g_hEditMsg, L"PDB File is successfully cached.\r\n");  // pending
            }
            else
            {
                appendTextOnEdit(g_hEditMsg, L"Error: PDB File is not cached.\r\n");
            }
        }

        if (hwnd == g_hBtnRegisterDLL)
        {
            wstring pathRegsrv32;
#ifdef _WIN64
            if (is32bit)
                pathRegsrv32 = L"C:\\Windows\\SysWOW64\\regsvr32.exe";
            else
                pathRegsrv32 = L"C:\\Windows\\System32\\regsvr32.exe";
#else
            if (is32bit)
                pathRegsrv32 = L"C:\\Windows\\System32\\regsvr32.exe";  // File system will redirect it to SysWOW64
            else
                pathRegsrv32 = L"C:\\Windows\\Sysnative\\regsvr32.exe";  // disable redirection on 64-bit OS. Will fail on 32-bit OS, which can't register 64-bit DLL anyway.
#endif
            ShellExecuteW(g_hMain, L"runas", pathRegsrv32.c_str(), (L"\"" + filePath + L"\"").c_str(), L"C:\\Windows\\System32", SHOW_OPENWINDOW);
        }

        if (hwnd == g_hBtnOpenProperties)
        {
            SHELLEXECUTEINFOW si{};
            si.cbSize = sizeof(si);
            si.fMask = SEE_MASK_INVOKEIDLIST;
            si.hwnd = g_hMain;
            si.lpVerb = L"properties";
            si.lpFile = filePath.c_str();
            si.lpParameters = nullptr;
            si.lpDirectory = nullptr;
            si.nShow = SHOW_OPENWINDOW;
            ShellExecuteExW(&si);
        }

        if (hwnd == g_hBtnConfig)
        {
            AllocConsole();
            HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
            HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
            writeConsole(hStdout, L"Current proxy server is: ");
            switch (proxyType)
            {
            case NetAsyncProxyType::Direct:
                writeConsole(hStdout, L"\"No proxy\"\n");
                break;
            case NetAsyncProxyType::System:
                writeConsole(hStdout, L"\"System proxy\"\n");
                break;
            case NetAsyncProxyType::UserSpecified:
                writeConsole(hStdout, g_proxyServer + L"\n");
                break;
            default:
                writeConsole(hStdout, L"\"Unknown\"\n");
                break;
            }
            writeConsole(hStdout, L"Current symbol server is: ");
            writeConsole(hStdout, g_symbolServerUsed);
            writeConsole(hStdout, L"\n");
            writeConsole(hStdout, L"\n");
            writeConsole(hStdout, L"What do you want to do:\n");
            writeConsole(hStdout, L" [0] Exit\n");
            writeConsole(hStdout, L" [1] Change the proxy server\n");
            writeConsole(hStdout, L" [2] Change the symbol server\n");
            writeConsole(hStdout, L"Your selection: ");
            wstring option = getStdin(hStdin);
            if (option == L"1")
            {
                writeConsole(hStdout, L"Enter the new proxy setting to use:\n");
                writeConsole(hStdout, L" [0] Keep the original proxy setting\n");
                writeConsole(hStdout, L" [1] Direct (no proxy)\n");
                writeConsole(hStdout, L" [2] System proxy\n");
                writeConsole(hStdout, L" [3] Enter a proxy server manually\n");
                writeConsole(hStdout, L"Your selection: ");
                option = getStdin(hStdin);
                if (option == L"1")
                {
                    proxyType = NetAsyncProxyType::Direct;
                    g_proxyServer = L"";
                }
                else if (option == L"2")
                {
                    proxyType = NetAsyncProxyType::System;
                    g_proxyServer = L"";
                }
                else if (option == L"3")
                {
                    proxyType = NetAsyncProxyType::UserSpecified;
                    writeConsole(hStdout, L"Enter the proxy server to use (hostname:port): ");
                    wstring userProxyServer = getStdin(hStdin);
                    g_proxyServer = userProxyServer;
                }
                else
                {
                    // no change
                }
            }
            else if (option == L"2")
            {
                writeConsole(hStdout, L"Enter the new symbol server to use:\n");
                writeConsole(hStdout, L" [0] Keep the original symbol server\n");
                writeConsole(hStdout, wstring(L" [1] Microsoft Symbol Server: ") + g_MicrosoftSymbolServerURL + L"\n");
                writeConsole(hStdout, wstring(L" [2] Mozilla Symbol Server: ") + g_MozillaSymbolServerURL + L"\n");
                writeConsole(hStdout, wstring(L" [3] Chromium Symbol Server: ") + g_ChromiumSymbolServerURL + L"\n");
                writeConsole(hStdout, wstring(L" [4] Unity 3D Symbol Server: ") + g_Unity3dSymbolServerURL + L"\n");
                writeConsole(hStdout, L" [5] Enter a symbol server manually\n");
                writeConsole(hStdout, L"Your selection: ");
                option = getStdin(hStdin);
                if (option == L"1")
                {
                    g_symbolServerUsed = g_MicrosoftSymbolServerURL;
                }
                else if (option == L"2")
                {
                    g_symbolServerUsed = g_MozillaSymbolServerURL;
                }
                else if (option == L"3")
                {
                    g_symbolServerUsed = g_ChromiumSymbolServerURL;
                }
                else if (option == L"4")
                {
                    g_symbolServerUsed = g_Unity3dSymbolServerURL;
                }
                else if (option == L"5")
                {
                    writeConsole(hStdout, L"Enter the symbol server to use: ");
                    wstring userSymbolServer = getStdin(hStdin);
                    if (userSymbolServer.find(L"http://") == 0 || userSymbolServer.find(L"https://") == 0)
                    {
                        g_symbolServerUsed = userSymbolServer;
                    }
                }
            }
            FreeConsole();
        }
    }
}

bool getFileSizeFromPath(const wstring& filePath, DWORD& filesize)
{
    filesize = 0;
    HANDLE h = CreateFileW(filePath.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    LARGE_INTEGER li;
    li.QuadPart = 0;
    bool isOK = GetFileSizeEx(h, &li);
    CloseHandle(h);
    if (isOK)
    {
        filesize = li.LowPart;  // we don't handle files larger than MAX_UNSIGNED_LONG
    }
    return isOK;
}
bool createDirectoryTreeForSpecifiedFile(const wstring& fileFullPath)
{
    // https://stackoverflow.com/questions/1530760/how-do-i-recursively-create-a-folder-in-win32
    wchar_t folder[MAX_PATH]{};
    const wchar_t* end;

    end = wcschr(fileFullPath.c_str(), L'\\');

    while (end != NULL)
    {
        wcsncpy_s(folder, fileFullPath.c_str(), end - fileFullPath.c_str() + 1);
        folder[MAX_PATH - 1] = 0;
        if (!CreateDirectoryW(folder, NULL))
        {
            DWORD err = GetLastError();

            if (err != ERROR_ALREADY_EXISTS)
            {
                // will reach here when create C:\ 
            }
        }
        end = wcschr(++end, L'\\');
    }
    return true;
}
void writeConsole(HANDLE hConsoleOutput, const std::wstring& str)
{
    DWORD len = 0;
    WriteConsoleW(hConsoleOutput, str.c_str(), static_cast<DWORD>(str.length()), &len, nullptr);
}
wstring getStdin(HANDLE hConsoleInput, bool trimNewLine)
{
    wchar_t inputBuf[200]{};
    DWORD wcharRead = 0;
    if (ReadConsoleW(hConsoleInput, inputBuf, _countof(inputBuf) - 1, &wcharRead, nullptr))
    {
        if (!trimNewLine)
        {
            return wstring(inputBuf);
        }
        else
        {
            wstring wholeLine(inputBuf);
            wholeLine.erase(std::remove(wholeLine.begin(), wholeLine.end(), '\n'), wholeLine.end());
            wholeLine.erase(std::remove(wholeLine.begin(), wholeLine.end(), '\r'), wholeLine.end());
            return wholeLine;
        }
    }
    else
    {
        return L"";
    }
}
void setDarkModeBasedOnSystemTheme()
{
    if (g_forceDarkMode)
    {
        g_isDarkMode = true;
        return;
    }
    if (g_forceLightMode)
    {
        g_isDarkMode = false;
        return;
    }
    DWORD dwUseLightTheme = 0;
    DWORD sizeOfDWORD = sizeof(DWORD);
    if (RegGetValueW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUseLightTheme", RRF_RT_REG_DWORD,
        nullptr, &dwUseLightTheme, &sizeOfDWORD) == ERROR_SUCCESS)
    {
        g_isDarkMode = (dwUseLightTheme == 0);
    }
    else
    {
        // if none is specified, use default, which is light theme
        g_isDarkMode = false;
    }
}