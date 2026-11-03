#pragma once

#include <cstdint>
#include <string>

namespace OSTPlatform::Http {

    struct Result {
        std::string body;
        uint32_t status = 0;
        // True once WinHTTP produced a response; callers must still check status for 2xx.
        bool ok = false;
    };

    Result Execute(const wchar_t* method,
                   const char* url,
                   const void* reqBody = nullptr,
                   uint32_t reqBodyLen = 0,
                   const wchar_t* headers = nullptr,
                   uint32_t timeoutResolve = 5000,
                   uint32_t timeoutConnect = 5000,
                   uint32_t timeoutSend = 10000,
                   uint32_t timeoutRecv = 10000,
                   // 响应体读到超过这个字节数就停止读取（不报错，r.body 是截断后的内容）。
                   // 默认 256KB 沿用之前写死在 Http.cpp 里的值；CDKey 的 /getTicketByCdkey、
                   // /appinfo 传 4MB（2026-11-03，调用方已按 10 参数写好，头文件没跟上导致编译失败）。
                   uint32_t maxBodyBytes = 256 * 1024);

} // namespace OSTPlatform::Http
