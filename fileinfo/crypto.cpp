#include "crypto.h"
#include <vector>
#include <sstream>

// Reference: https://stackoverflow.com/questions/13256446/compute-md5-hash-value-by-c-winapi
std::wstring GetHashText(const void* data, const unsigned long data_size, HashType hashType)
{
    HCRYPTPROV hProv = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return L"";
    }

    BOOL hash_ok = FALSE;
    HCRYPTPROV hHash = NULL;
    switch (hashType) {
    case HashType::HashSha1: hash_ok = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash); break;
    case HashType::HashMd5: hash_ok = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash); break;
    case HashType::HashSha256: hash_ok = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash); break;
    }

    if (!hash_ok) {
        CryptReleaseContext(hProv, 0);
        return L"";
    }

    if (!CryptHashData(hHash, static_cast<const BYTE*>(data), data_size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return L"";
    }

    DWORD cbHashSize = 0, dwCount = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)& cbHashSize, &dwCount, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return L"";
    }

    std::vector<BYTE> buffer(cbHashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, reinterpret_cast<BYTE*>(&buffer[0]), &cbHashSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return L"";
    }

    std::wstringstream oss;

    for (std::vector<BYTE>::const_iterator iter = buffer.begin(); iter != buffer.end(); ++iter) {
        oss.fill('0');
        oss.width(2);
        oss << std::hex << static_cast<const int>(*iter);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}
