#pragma once

#include <Windows.h>
#include <Wincrypt.h>
#include <string>
enum class HashType
{
    HashSha1, HashMd5, HashSha256
};

// Reference: https://stackoverflow.com/questions/13256446/compute-md5-hash-value-by-c-winapi
std::wstring GetHashText(const void* data, const unsigned long data_size, HashType hashType);