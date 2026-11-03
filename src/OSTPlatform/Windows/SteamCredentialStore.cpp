#include "include/SteamCredentialStore.h"

#include "include/Log.h"
#include "include/Numbers.h"
#include "include/Encoding.h"
#include "Windows/Handles.h"

#include <windows.h>

#include <utility>

namespace OSTPlatform::SteamCredentialStore {
namespace {

constexpr const wchar_t* kValueSteamId = L"SteamID";
constexpr const wchar_t* kValueAppTicket = L"AppTicket";
constexpr const wchar_t* kValueAppTicketExpTime = L"AppTicketExpTime";
constexpr const wchar_t* kValueEncryptedTicket = L"ETicket";
constexpr const wchar_t* kActiveProcessKeyPath = L"Software\\Valve\\Steam\\ActiveProcess";
constexpr const wchar_t* kValueActiveUser = L"ActiveUser";
constexpr const wchar_t* kValueUniverse = L"Universe";
constexpr const wchar_t* kValueDenuvo = L"Denuvo";   //判断
constexpr const wchar_t* kValueDenuvoExpired = L"DenuvoExpired";   //判断
constexpr const wchar_t* kValueSteamDrm = L"SteamDrm";   //判断
constexpr const wchar_t* kValueCDKey = L"CDKey";   //判断

std::wstring SteamAppKeyPath(uint32_t appId) {
    return L"Software\\Valve\\Steam\\Apps\\" + std::to_wstring(appId);
}

const char* ValueNameForLog(PCWSTR valueName) {
    if (valueName == kValueSteamId) return "SteamID";
    if (valueName == kValueAppTicket) return "AppTicket";
    if (valueName == kValueEncryptedTicket) return "ETicket";
    if (valueName == kValueActiveUser) return "ActiveUser";
    if (valueName == kValueUniverse) return "Universe";
    if (valueName == kValueDenuvo) return "Denuvo";
    if (valueName == kValueDenuvoExpired) return "DenuvoExpired";
    if (valueName == kValueSteamDrm) return "SteamDrm";
    if (valueName == kValueCDKey) return "CDKey";
    if (valueName == kValueAppTicketExpTime) return "AppTicketExpTime";
    return "?";
}

Status FromLStatus(LSTATUS status) {
    switch (status) {
    case ERROR_SUCCESS:
        return Status::Ok;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_NOT_FOUND:
        return Status::NotFound;
    default:
        return Status::Failed;
    }
}

// RegGetValueW does the size-dance for us: first call (pvData == nullptr)
// reports the byte count, second fills the buffer. `out` is overwritten only on
// success; left untouched on any failure.
LSTATUS ReadBinaryValue(uint32_t appId, PCWSTR valueName, std::vector<uint8_t>& out) {
    const std::wstring keyPath = SteamAppKeyPath(appId);

    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), valueName,
                                  RRF_RT_REG_BINARY, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: {} missing for appid={} status={}",
                           ValueNameForLog(valueName), appId, status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to query {} size for appid={} status={}",
                          ValueNameForLog(valueName), appId, status);
        }
        return status;
    }
    if (bytes == 0) {
        OSTP_LOG_DEBUG("SteamCredentialStore: {} empty for appid={}", ValueNameForLog(valueName), appId);
        out.clear();
        return ERROR_SUCCESS;
    }

    std::vector<uint8_t> buffer(bytes);
    status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), valueName,
                          RRF_RT_REG_BINARY, nullptr, buffer.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to read {} for appid={} status={}",
                      ValueNameForLog(valueName), appId, status);
        return status;
    }

    buffer.resize(bytes);
    out = std::move(buffer);
    OSTP_LOG_DEBUG("SteamCredentialStore: read {} for appid={} bytes={}",
                   ValueNameForLog(valueName), appId, out.size());
    return ERROR_SUCCESS;
}

// Create-or-open the per-app key and set a single value. REG_OPTION_NON_VOLATILE
// + KEY_SET_VALUE mirrors what Steam itself uses for these credential entries.
LSTATUS WriteValue(uint32_t appId, PCWSTR valueName, DWORD type, const BYTE* data, DWORD bytes) {
    Windows::UniqueRegKey key;
    LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, SteamAppKeyPath(appId).c_str(), 0, nullptr,
                                     REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, key.put(), nullptr);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to create/open app key appid={} status={}", appId, status);
        return status;
    }

    status = RegSetValueExW(key.get(), valueName, 0, type, data, bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to write {} for appid={} bytes={} status={}",
                      ValueNameForLog(valueName), appId, bytes, status);
        return status;
    }

    OSTP_LOG_INFO("SteamCredentialStore: wrote {} for appid={} bytes={}",
                  ValueNameForLog(valueName), appId, bytes);
    return ERROR_SUCCESS;
}

} // namespace

const char* ToString(Status status) {
    switch (status) {
    case Status::Ok: return "Ok";
    case Status::NotFound: return "NotFound";
    case Status::Unsupported: return "Unsupported";
    case Status::Failed: return "Failed";
    }
    return "Unknown";
}

Status GetAppTicket(uint32_t appId, std::vector<uint8_t>& ticket) {
    return FromLStatus(ReadBinaryValue(appId, kValueAppTicket, ticket));
}

Status WriteAppTicket(uint32_t appId, const std::vector<uint8_t>& data) {
    return FromLStatus(WriteValue(appId, kValueAppTicket, REG_BINARY,
                                  reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size())));
}

Status GetETicket(uint32_t appId, std::vector<uint8_t>& ticket) {
    return FromLStatus(ReadBinaryValue(appId, kValueEncryptedTicket, ticket));
}

Status WriteETicket(uint32_t appId, const std::vector<uint8_t>& data) {
    return FromLStatus(WriteValue(appId, kValueEncryptedTicket, REG_BINARY,
                                  reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size())));
}

Status GetSteamId(uint32_t appId, uint64_t& steamId) {
    const std::wstring keyPath = SteamAppKeyPath(appId);

    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), kValueSteamId,
                                  RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: SteamID missing for appid={} status={}", appId, status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to query SteamID size for appid={} status={}", appId, status);
        }
        return mapped;
    }
    if (bytes < sizeof(wchar_t)) {
        OSTP_LOG_WARN("SteamCredentialStore: SteamID value too short for appid={} bytes={}", appId, bytes);
        return Status::NotFound;
    }

    std::wstring raw(bytes / sizeof(wchar_t), L'\0');
    status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), kValueSteamId,
                          RRF_RT_REG_SZ, nullptr, raw.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to read SteamID for appid={} status={}", appId, status);
        return FromLStatus(status);
    }

    // RegGetValueW guarantees a single null terminator and counts it in `bytes`;
    // drop it so the parser sees only digits.
    const size_t chars = bytes / sizeof(wchar_t);
    raw.resize(chars > 0 ? chars - 1 : 0);

    // A present-but-empty/zero/unparseable value is treated as "no credential".
    const auto parsed = Numbers::ParseUInt64(raw);
    if (!parsed || *parsed == 0) {
        OSTP_LOG_WARN("SteamCredentialStore: SteamID value invalid for appid={}", appId);
        return Status::NotFound;
    }

    steamId = *parsed;
    OSTP_LOG_DEBUG("SteamCredentialStore: read SteamID for appid={} steamid={}", appId, steamId);
    return Status::Ok;
}

Status WriteSteamId(uint32_t appId, uint64_t steamId) {
    const std::wstring value = std::to_wstring(steamId);
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return FromLStatus(WriteValue(appId, kValueSteamId, REG_SZ,
                                  reinterpret_cast<const BYTE*>(value.c_str()), bytes));
}

Status GetActiveUser(uint32_t& accountId, std::wstring& universe) {
    DWORD activeUser = 0;
    DWORD bytes = sizeof(activeUser);
    LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, kActiveProcessKeyPath, kValueActiveUser,
                                  RRF_RT_REG_DWORD, nullptr, &activeUser, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: ActiveUser missing status={}", status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to read ActiveUser status={}", status);
        }
        return mapped;
    }
    if (bytes != sizeof(activeUser)) {
        OSTP_LOG_WARN("SteamCredentialStore: ActiveUser has unexpected size bytes={}", bytes);
        return Status::NotFound;
    }
    if (activeUser == 0) {
        OSTP_LOG_DEBUG("SteamCredentialStore: ActiveUser is zero");
        return Status::NotFound;
    }

    bytes = 0;
    status = RegGetValueW(HKEY_CURRENT_USER, kActiveProcessKeyPath, kValueUniverse,
                          RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        const auto mapped = FromLStatus(status);
        if (mapped == Status::NotFound) {
            OSTP_LOG_DEBUG("SteamCredentialStore: ActiveProcess Universe missing status={}", status);
        } else {
            OSTP_LOG_WARN("SteamCredentialStore: failed to query ActiveProcess Universe size status={}", status);
        }
        return mapped;
    }
    if (bytes < sizeof(wchar_t)) {
        OSTP_LOG_WARN("SteamCredentialStore: ActiveProcess Universe value too short bytes={}", bytes);
        return Status::NotFound;
    }

    std::wstring rawUniverse(bytes / sizeof(wchar_t), L'\0');
    status = RegGetValueW(HKEY_CURRENT_USER, kActiveProcessKeyPath, kValueUniverse,
                          RRF_RT_REG_SZ, nullptr, rawUniverse.data(), &bytes);
    if (status != ERROR_SUCCESS) {
        OSTP_LOG_WARN("SteamCredentialStore: failed to read ActiveProcess Universe status={}", status);
        return FromLStatus(status);
    }

    const size_t chars = bytes / sizeof(wchar_t);
    rawUniverse.resize(chars > 0 ? chars - 1 : 0);
    if (rawUniverse.empty()) {
        OSTP_LOG_WARN("SteamCredentialStore: ActiveProcess Universe is empty");
        return Status::NotFound;
    }

    accountId = activeUser;
    universe = std::move(rawUniverse);
    OSTP_LOG_DEBUG("SteamCredentialStore: read ActiveUser accountid={} universe={}({} chars)",
                   accountId, Encoding::WideToUtf8(universe), universe.size());
    return Status::Ok;
}

// 写入 DenuvoFlag, 过期DenuvoFlag
Status WriteDenuvoFlag(uint32_t appId, bool isDenuvo, bool isExpiredDenuvo, bool isSteamDrm, const std::string& cdkey) {
    OSTP_LOG_DEBUG("SteamCredentialStore: write appId={} Denuvo={} DenuvoExpired={} SteamDrm={}",
                   appId, isDenuvo, isExpiredDenuvo, isSteamDrm);
    DWORD v1 = isDenuvo ? 1u : 0u;  
    DWORD v2 = isExpiredDenuvo ? 1u : 0u;  
    DWORD v3 = isSteamDrm ? 1u : 0u;  

    Status s1 = FromLStatus(WriteValue(appId, kValueDenuvo, REG_DWORD,
                                       reinterpret_cast<const BYTE*>(&v1), sizeof(v1)));  
    Status s2 = FromLStatus(WriteValue(appId, kValueDenuvoExpired, REG_DWORD,  
                                       reinterpret_cast<const BYTE*>(&v2), sizeof(v2)));
    Status s3 = FromLStatus(WriteValue(appId, kValueSteamDrm, REG_DWORD,  
                                       reinterpret_cast<const BYTE*>(&v3), sizeof(v3)));                                   
    const std::wstring wideKey = Encoding::Utf8ToWide(cdkey);
    Status s4 = FromLStatus(WriteValue(appId, kValueCDKey, REG_SZ,
                                       reinterpret_cast<const BYTE*>(wideKey.c_str()),
                                       static_cast<DWORD>((wideKey.size() + 1) * sizeof(wchar_t))));
    // 日志里不打 cdkey 原文（明文 key 进日志等于泄露）。
    OSTP_LOG_DEBUG("SteamCredentialStore: write appId={} status1={} status2={} status3={} status4={}",
                   appId, ToString(s1), ToString(s2), ToString(s3), ToString(s4));
    return Status::Ok;
}
  
// 读取  DenuvoFlag,过期DenuvoFlag
Status GetDenuvoFlag(uint32_t appId, bool& isDenuvo, bool& isExpiredDenuvo, bool& isSteamDrm, std::string& cdkey) {
    OSTP_LOG_DEBUG("SteamCredentialStore: read GetDenuvoFlag appId={}", appId); 
    const std::wstring keyPath = SteamAppKeyPath(appId);
    DWORD denuvo = 0, bytes = sizeof(denuvo);  
    LSTATUS s1 = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(),  
                              kValueDenuvo, RRF_RT_REG_DWORD, nullptr,  
                              &denuvo, &bytes);// 写 DWORD，不是 bool  
    if (s1 != ERROR_SUCCESS || bytes != sizeof(denuvo)) {  
        isDenuvo = false;   // 读不到按 false，不打 warn（首次必然读不到，warn 会刷屏）  
    } else {  
        isDenuvo = (denuvo != 0);  
    }  
  
    DWORD expired = 0;  
    bytes = sizeof(expired);// 复用 bytes，不要重新定义  
    LSTATUS s2 = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(),  
                              kValueDenuvoExpired, RRF_RT_REG_DWORD, nullptr,  
                              &expired, &bytes);  
    if (s2 != ERROR_SUCCESS || bytes != sizeof(expired)) {  
        isExpiredDenuvo = false;  
    } else {  
        isExpiredDenuvo = (expired != 0);  
    }

    DWORD steamDrm = 0;  
    bytes = sizeof(steamDrm);// 复用 bytes，不要重新定义  
    LSTATUS s3 = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(),  
                              kValueSteamDrm, RRF_RT_REG_DWORD, nullptr,  
                              &steamDrm, &bytes);  
    if (s3 != ERROR_SUCCESS || bytes != sizeof(steamDrm)) {  
        isSteamDrm = false;  
    } else {  
        isSteamDrm = (steamDrm != 0);  
    }


    // 读字符串  
    wchar_t buf[512]{};// 自动零初始化  
    DWORD keyBytes = sizeof(buf);  // 不能再叫 bytes：上面已经定义过同名变量
    // s4：s3 已被上面的 SteamDrm 读取占用，同名会 C2374。
    LSTATUS s4 = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(),
                              kValueCDKey,
                              RRF_RT_REG_SZ, nullptr, buf, &keyBytes);
    if (s4 != ERROR_SUCCESS || keyBytes < sizeof(wchar_t)) {
        cdkey.clear();// 读不到 = 空串  
    } else {  
        cdkey = Encoding::WideToUtf8(buf);// buf 保证 null 结尾  
    }  
  
    return Status::Ok;  
}

bool HasDrmFlags(uint32_t appId) {
    const std::wstring keyPath = SteamAppKeyPath(appId);
    for (PCWSTR name : {kValueDenuvo, kValueDenuvoExpired, kValueSteamDrm}) {
        // 只问存不存在：pvData 传 nullptr，RegGetValueW 只返回状态。
        if (RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), name, RRF_RT_REG_DWORD,
                         nullptr, nullptr, nullptr) == ERROR_SUCCESS)
            return true;
    }
    return false;
}

Status WriteDrmFlags(uint32_t appId, bool isDenuvo, bool isExpiredDenuvo, bool isSteamDrm) {
    const DWORD v1 = isDenuvo ? 1u : 0u;
    const DWORD v2 = isExpiredDenuvo ? 1u : 0u;
    const DWORD v3 = isSteamDrm ? 1u : 0u;
    const Status s1 = FromLStatus(WriteValue(appId, kValueDenuvo, REG_DWORD,
                                             reinterpret_cast<const BYTE*>(&v1), sizeof(v1)));
    const Status s2 = FromLStatus(WriteValue(appId, kValueDenuvoExpired, REG_DWORD,
                                             reinterpret_cast<const BYTE*>(&v2), sizeof(v2)));
    const Status s3 = FromLStatus(WriteValue(appId, kValueSteamDrm, REG_DWORD,
                                             reinterpret_cast<const BYTE*>(&v3), sizeof(v3)));
    OSTP_LOG_DEBUG("SteamCredentialStore: write drm flags appId={} Denuvo={} DenuvoExpired={} SteamDrm={} status={}/{}/{}",
                   appId, isDenuvo, isExpiredDenuvo, isSteamDrm, ToString(s1), ToString(s2), ToString(s3));
    if (s1 != Status::Ok) return s1;
    if (s2 != Status::Ok) return s2;
    return s3;
}

Status GetAppTicketExpTime(uint32_t appId, uint64_t& expiresAt) {
    const std::wstring keyPath = SteamAppKeyPath(appId);
    ULONGLONG value = 0;
    DWORD bytes = sizeof(value);
    const LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, keyPath.c_str(), kValueAppTicketExpTime,
                                        RRF_RT_REG_QWORD, nullptr, &value, &bytes);
    if (status != ERROR_SUCCESS) return FromLStatus(status);
    expiresAt = static_cast<uint64_t>(value);
    return Status::Ok;
}

Status WriteAppTicketExpTime(uint32_t appId, uint64_t expiresAt) {
    const ULONGLONG value = static_cast<ULONGLONG>(expiresAt);
    return FromLStatus(WriteValue(appId, kValueAppTicketExpTime, REG_QWORD,
                                  reinterpret_cast<const BYTE*>(&value), sizeof(value)));
}

} // namespace OSTPlatform::SteamCredentialStore