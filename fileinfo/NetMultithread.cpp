#include "NetMultithread.h"

NetMultithread::NetMultithread()
{
    init(DEFAULT_USER_AGENT);
}

NetMultithread::NetMultithread(std::wstring userAgent)
{
    init(userAgent);
}

NetMultithread::~NetMultithread()
{
    for (auto i : this->vecDownloader)
    {
        delete[] i;
    }
}

void NetMultithread::init(std::wstring userAgent)
{
    this->userAgent = userAgent;
}
