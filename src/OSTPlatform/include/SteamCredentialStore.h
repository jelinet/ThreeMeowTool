#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace OSTPlatform::SteamCredentialStore {

    enum class Status {
        Ok,
        NotFound,
        Unsupported,
        Failed,
    };

    const char* ToString(Status status);

    // Read/write Steam per-app credentials. Each Get* reader writes its
    // out-parameter only on Status::Ok; on any other status the out-parameter is
    // left untouched. The signatures mirror their Write* counterparts so a value
    // travels through the same shape going in and coming out.
    Status GetAppTicket(uint32_t appId, std::vector<uint8_t>& ticket);
    Status WriteAppTicket(uint32_t appId, const std::vector<uint8_t>& data);

    Status GetETicket(uint32_t appId, std::vector<uint8_t>& ticket);
    Status WriteETicket(uint32_t appId, const std::vector<uint8_t>& data);

    Status GetSteamId(uint32_t appId, uint64_t& steamId);
    Status WriteSteamId(uint32_t appId, uint64_t steamId);

    Status GetActiveUser(uint32_t& accountId, std::wstring& universe);

    // 写入  DenuvoFlag
    // cdkey 是 UTF-8，内部转成 REG_SZ 写进 Apps\<appid>\CDKey。
    Status WriteDenuvoFlag(uint32_t appId, bool isDenuvo, bool isExpiredDenuvo, bool isSteamDrm, const std::string& cdkey);
  
    // 读取  DenuvoFlag
    // 读不到的值按默认（false / 空串）返回，永远返回 Ok。
    Status GetDenuvoFlag(uint32_t appId, bool& isDenuvo, bool& isExpiredDenuvo, bool& isSteamDrm, std::string& cdkey);

    // Denuvo / DenuvoExpired / SteamDrm 三个值里至少有一个存在就返回 true。
    // GetDenuvoFlag 读不到时一律按 false 返回，分不清"写过 0"和"从没写过"，兜底请求 /appinfo 要靠这个区分。
    bool HasDrmFlags(uint32_t appId);

    // 只写三个 DRM 标记，不碰 CDKey（WriteDenuvoFlag 会顺带写 CDKey，/appinfo 兜底时手里没有 cdkey）。
    Status WriteDrmFlags(uint32_t appId, bool isDenuvo, bool isExpiredDenuvo, bool isSteamDrm);

    // AppTicket 过期时间（Unix 秒），REG_QWORD 存在 Apps\<appid>\AppTicketExpTime。
    // 读不到返回 NotFound，expiresAt 不改。
    Status GetAppTicketExpTime(uint32_t appId, uint64_t& expiresAt);
    Status WriteAppTicketExpTime(uint32_t appId, uint64_t expiresAt);

} // namespace OSTPlatform::SteamCredentialStore
