#include "Config.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/ManifestClient.h"

#include <toml++/toml.hpp>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <mutex>

#include "OSTPlatform/include/Encoding.h"

// 读 cdkey 的注册表配置用
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace Config {
namespace {

    struct Snapshot {
        std::string manifestProvider = "20770407";
        bool manifestFailover = true;
        ManifestTimeouts manifestTimeouts;
        LogLevel logLevel = LogLevel::Debug;
        std::string logDir;
        std::vector<std::string> luaPaths;
        std::vector<std::string> remoteUrlTemplates;
        // std::string remoteOrder = "gh-proxy-first";
        bool statsEnableApi = true;
        std::string presenceDisplay = "spacewar";
        InjectionSettings injection;
        CloudSettings cloud;
        CdkeySettings cdkey;
    };

    std::mutex g_mutex;
    bool g_loadedOnce = false;

    // order 归一化成小写再比对，避免大小写写错导致回退顺序不符合预期
    static std::string NormalizeRemoteOrder(std::string s) {
        for (auto& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    const char* ToString(LogLevel level) {
        switch (level) {
        case LogLevel::Trace: return "trace";
        case LogLevel::Debug: return "debug";
        case LogLevel::Info:  return "info";
        case LogLevel::Warn:  return "warn";
        case LogLevel::Error: return "error";
        }
        return "???";
    }

    Snapshot MakeDefaultSnapshot(const std::string& configPath) {
        Snapshot snapshot;
        std::filesystem::path p(configPath);
        snapshot.logDir = (p.parent_path() / "opensteamtool").string();
        return snapshot;
    }

    void ApplySnapshot(const Snapshot& snapshot) {
        manifestTimeoutResolve = snapshot.manifestTimeouts.resolve;
        manifestTimeoutConnect = snapshot.manifestTimeouts.connect;
        manifestTimeoutSend    = snapshot.manifestTimeouts.send;
        manifestTimeoutRecv    = snapshot.manifestTimeouts.recv;
        manifestFailover       = snapshot.manifestFailover;
        logLevel               = snapshot.logLevel;
        logDir                 = snapshot.logDir;
        luaPaths               = snapshot.luaPaths;
        remoteUrlTemplates     = snapshot.remoteUrlTemplates;
        // remoteOrder            = snapshot.remoteOrder;
        statsEnableApi         = snapshot.statsEnableApi;
        presenceDisplay        = snapshot.presenceDisplay;
        injectEnabled          = snapshot.injection.enabled;
        injectLibraryX86       = snapshot.injection.libraryX86;
        injectLibraryX64       = snapshot.injection.libraryX64;
        cloudEnabled           = snapshot.cloud.enabled;
        cloudLibrary           = snapshot.cloud.library;
        cdkeyBaseUrl           = snapshot.cdkey.baseUrl;
        cdkeyAuthToken         = snapshot.cdkey.authToken;
        cdkeyTimeoutMs         = snapshot.cdkey.timeoutMs;
    }

    constexpr wchar_t kCdkeyRegistryKey[] = L"SOFTWARE\\OpenSteamTool\\CDKey";

    // 读 HKLM\<kCdkeyRegistryKey> 下的一个 REG_SZ。值不存在、为空、类型不对都返回空字符串。
    // RRF_SUBKEY_WOW6464KEY：固定读 64 位视图，跟 64 位 PowerShell 写入的位置一致；
    // 不加的话 32 位进程会被重定向到 WOW6432Node，读不到（同 CDKeyReporter.cpp 的 GetMachineId）。
    std::string ReadCdkeyRegistryString(const wchar_t* valueName) {
        DWORD bytes = 0;
        LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, kCdkeyRegistryKey, valueName,
                                      RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, nullptr, &bytes);
        if (status != ERROR_SUCCESS || bytes <= sizeof(wchar_t)) {
            if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND)
                LOG_WARN("cdkey registry: failed to query {} ({})",
                         OSTPlatform::Encoding::WideToUtf8(valueName), static_cast<long>(status));
            return std::string();
        }
        // RegGetValueW 保证结尾有 '\0' 且算在 bytes 里，所以多分配不会截断。
        std::wstring buf(bytes / sizeof(wchar_t), L'\0');
        status = RegGetValueW(HKEY_LOCAL_MACHINE, kCdkeyRegistryKey, valueName,
                              RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, buf.data(), &bytes);
        if (status != ERROR_SUCCESS) {
            LOG_WARN("cdkey registry: failed to read {} ({})",
                     OSTPlatform::Encoding::WideToUtf8(valueName), static_cast<long>(status));
            return std::string();
        }
        buf.resize(wcsnlen(buf.c_str(), buf.size()));
        return OSTPlatform::Encoding::WideToUtf8(buf);
    }

    // base_url / auth_token 只从注册表读，不再放 toml（2026-10-19 和使用者确认）：
    // 换/覆盖 opensteamtool.toml 时 token 不会被冲掉，也不会随配置文件被复制走。
    // 只读 HKLM（整台机器共用），不读 HKCU（2026-10-19 和使用者确认）：
    // 先做过只读 HKCU 的版本，但提权时换成别的管理员账户、或机器上有多个 Windows 账户时，值会写进别人的 HKCU、Steam 读不到。
    // 代价是写入要管理员权限，所有账户都能读到同一个 token。
    // 每次 Load 都重读，但 Load 只在 toml 变化 / 启动时触发：只改注册表不会立即生效，要 touch 一下 toml 或重启 Steam。
    // 写入示例（管理员 cmd；/reg:64 保证写 64 位视图）：
    //   reg add HKLM\SOFTWARE\OpenSteamTool\CDKey /v BaseUrl   /t REG_SZ /d "https://xxx.workers.dev" /f /reg:64
    //   reg add HKLM\SOFTWARE\OpenSteamTool\CDKey /v AuthToken /t REG_SZ /d "<token>" /f /reg:64
    void ReadCdkeyRegistry(CdkeySettings& cdkey) {
        std::string url = ReadCdkeyRegistryString(L"BaseUrl");
        // 去掉末尾 '/'，免得和 "/cdkeycheck" 拼出 "//cdkeycheck"。
        while (!url.empty() && url.back() == '/') url.pop_back();
        cdkey.baseUrl = std::move(url);

        std::string token = ReadCdkeyRegistryString(L"AuthToken");
        // 含 CR/LF 的 token 会让人往请求头里塞额外的头（header injection），直接丢弃。
        if (token.find_first_of("\r\n") == std::string::npos)
            cdkey.authToken = std::move(token);
        else
            LOG_WARN("cdkey registry AuthToken contains CR/LF, ignored");
    }

    void ApplyManifestProvider(const std::string& provider) {
        if (!ManifestClient::SetProvider(provider)) {
            LOG_WARN("Unknown manifest.url \"{}\", keeping default", provider);
            ManifestClient::SetProvider("20770407");
        }
    }

    // WinHTTP 把零超时读成无限等待，负数经转换会回绕成极大值；
    // 两种取值都会让单次尝试跑穿取码预算，因此在入口处钳制并告警。
    void ReadTimeoutMs(const toml::table& manifest, const char* key, uint32_t& out) {
        const auto val = manifest[key].value<int64_t>();
        if (!val) return;

        constexpr int64_t kMin = 1;
        constexpr int64_t kMax = ManifestClient::kFetchBudgetMs;
        if (*val < kMin || *val > kMax) {
            LOG_WARN("manifest.{} = {} is outside [{}, {}], clamping", key, *val, kMin, kMax);
        }
        out = static_cast<uint32_t>(std::clamp<int64_t>(*val, kMin, kMax));
    }

    LoadResult ApplySnapshotLocked(const Snapshot& snapshot) {
        std::lock_guard lock(g_mutex);
        LoadResult result;
        result.luaPathsChanged = luaPaths != snapshot.luaPaths;
        ApplySnapshot(snapshot);
        g_loadedOnce = true;
        result.applied = true;
        return result;
    }

} // namespace

        LoadResult Load(const std::string& configPath) {
        Snapshot snapshot = MakeDefaultSnapshot(configPath);
        ReadCdkeyRegistry(snapshot.cdkey);
        if (!std::filesystem::exists(configPath)) {
            LOG_INFO("Config file not found, using defaults");
            ApplyManifestProvider(snapshot.manifestProvider);
            LoadResult result = ApplySnapshotLocked(snapshot);
            LOG_INFO("Config loaded: manifest.url={} log.level={} lua.paths={} stats.enable_api={} remote.url_templates={}",
                     ManifestClient::ActiveProviderName(),
                     ToString(GetLogLevel()),
                     (uint32_t)GetLuaPaths().size(),
                     GetStatsEnableApi(),
                     (uint32_t)GetRemoteUrlTemplates().size());
            return result;
        }

        try {
            auto tbl = toml::parse_file(configPath);

            // [manifest]
            if (auto manifest = tbl["manifest"].as_table()) {
                if (auto val = (*manifest)["url"].value<std::string>()) {
                    snapshot.manifestProvider = *val;
                }
                if (auto val = (*manifest)["failover"].value<bool>()) {
                    snapshot.manifestFailover = *val;
                }
                ReadTimeoutMs(*manifest, "timeout_resolve_ms", snapshot.manifestTimeouts.resolve);
                ReadTimeoutMs(*manifest, "timeout_connect_ms", snapshot.manifestTimeouts.connect);
                ReadTimeoutMs(*manifest, "timeout_send_ms", snapshot.manifestTimeouts.send);
                ReadTimeoutMs(*manifest, "timeout_recv_ms", snapshot.manifestTimeouts.recv);
            }

            // [log]
            if (auto log = tbl["log"].as_table()) {
                if (auto val = (*log)["level"].value<std::string>()) {
                    if (*val == "trace")           snapshot.logLevel = LogLevel::Trace;
                    else if (*val == "debug")       snapshot.logLevel = LogLevel::Debug;
                    else if (*val == "info")        snapshot.logLevel = LogLevel::Info;
                    else if (*val == "warn")        snapshot.logLevel = LogLevel::Warn;
                    else if (*val == "error")       snapshot.logLevel = LogLevel::Error;
                }
            }

            // [lua]
            if (auto lua = tbl["lua"].as_table()) {
                if (auto arr = (*lua)["paths"].as_array()) {
                    for (auto& elem : *arr) {
                        if (auto str = elem.value<std::string>()) {
                            snapshot.luaPaths.push_back(*str);
                        }
                    }
                }
            }

            // [remote] — url_template may be a single string or an array of strings.
            if (auto remote = tbl["remote"].as_table()) {
                if (auto arr = (*remote)["url_template"].as_array()) {
                    for (auto& elem : *arr) {
                        if (auto str = elem.value<std::string>()) {
                            snapshot.remoteUrlTemplates.push_back(*str);
                        }
                    }
                } else if (auto val = (*remote)["url_template"].value<std::string>()) {
                    snapshot.remoteUrlTemplates.push_back(*val);
                }
            }

            // [stats]
            if (auto stats = tbl["stats"].as_table()) {
                if (auto val = (*stats)["enable_api"].value<bool>()) {
                    snapshot.statsEnableApi = *val;
                }
            }

            // [presence]
            if (auto presence = tbl["presence"].as_table()) {
                if (auto val = (*presence)["display"].value<std::string>()) {
                    snapshot.presenceDisplay = *val;
                }
            }

            // [inject]
            if (auto inject = tbl["inject"].as_table()) {
                if (auto val = (*inject)["enabled"].value<bool>())
                    snapshot.injection.enabled = *val;
                if (auto val = (*inject)["library_x86"].value<std::string>())
                    snapshot.injection.libraryX86 = *val;
                if (auto val = (*inject)["library_x64"].value<std::string>())
                    snapshot.injection.libraryX64 = *val;
            }

            // [cloud]
            if (auto cloud = tbl["cloud"].as_table()) {
                if (auto val = (*cloud)["enabled"].value<bool>())
                    snapshot.cloud.enabled = *val;
                if (auto val = (*cloud)["library"].value<std::string>())
                    snapshot.cloud.library = *val;
            }

            // [cdkey]
            if (auto cdkey = tbl["cdkey"].as_table()) {
                // base_url / auth_token 已挪到注册表（见 ReadCdkeyRegistry），toml 里还写着就提醒删掉。
                if (cdkey->contains("base_url") || cdkey->contains("auth_token"))
                    LOG_WARN("cdkey.base_url/auth_token in toml are ignored, set them in registry HKLM\\SOFTWARE\\OpenSteamTool\\CDKey");
                if (auto val = (*cdkey)["timeout_ms"].value<int64_t>())
                    snapshot.cdkey.timeoutMs = static_cast<uint32_t>(*val);
            }

            ApplyManifestProvider(snapshot.manifestProvider);
            ManifestClient::SetFailoverEnabled(snapshot.manifestFailover);
            LoadResult result = ApplySnapshotLocked(snapshot);
            LOG_INFO("Config loaded: manifest.url={} manifest.failover={} log.level={} lua.paths={} stats.enable_api={} remote.url_template={}",
                     ManifestClient::ActiveProviderName(),
                     ManifestClient::IsFailoverEnabled(),
                     ToString(snapshot.logLevel),
                     (uint32_t)snapshot.luaPaths.size(),
                     snapshot.statsEnableApi,
                     (uint32_t)snapshot.remoteUrlTemplates.size());
            return result;

        } catch (const toml::parse_error& e) {
            LOG_WARN("Config parse error: {}", e.what());
        } catch (...) {
            LOG_WARN("Config load failed");
        }
        bool shouldApplyDefault = false;
        {
            std::lock_guard lock(g_mutex);
            shouldApplyDefault = !g_loadedOnce;
        }
        if (shouldApplyDefault) {
            ApplyManifestProvider(snapshot.manifestProvider);
            ManifestClient::SetFailoverEnabled(snapshot.manifestFailover);
            std::lock_guard lock(g_mutex);
            const bool luaChanged = luaPaths != snapshot.luaPaths;
            ApplySnapshot(snapshot);
            g_loadedOnce = true;
            return {true, luaChanged};
        }
        return {};
    }

    ManifestTimeouts GetManifestTimeouts() {
        std::lock_guard lock(g_mutex);
        return {
            manifestTimeoutResolve,
            manifestTimeoutConnect,
            manifestTimeoutSend,
            manifestTimeoutRecv,
        };
    }

    LogLevel GetLogLevel() {
        std::lock_guard lock(g_mutex);
        return logLevel;
    }

    std::string GetLogDir() {
        std::lock_guard lock(g_mutex);
        return logDir;
    }

    std::vector<std::string> GetLuaPaths() {
        std::lock_guard lock(g_mutex);
        return luaPaths;
    }

    std::vector<std::string> GetRemoteUrlTemplates() {
        std::lock_guard lock(g_mutex);
        return remoteUrlTemplates;
    }

    // std::string GetRemoteOrder() {
    //     std::lock_guard lock(g_mutex);
    //     return remoteOrder;
    // }

    InjectionSettings GetInjectionSettings() {
        std::lock_guard lock(g_mutex);
        return {
            injectEnabled,
            injectLibraryX86,
            injectLibraryX64,
        };
    }

    bool GetStatsEnableApi() {
        std::lock_guard lock(g_mutex);
        return statsEnableApi;
    }

    bool GetPresenceBroadcastEnabled() {
        std::lock_guard lock(g_mutex);
        return presenceDisplay != "none";
    }

    CloudSettings GetCloudSettings() {
        std::lock_guard lock(g_mutex);
        return {
            cloudEnabled,
            cloudLibrary,
        };
    }

    CdkeySettings GetCdkeySettings() {
        std::lock_guard lock(g_mutex);
        return {
            cdkeyBaseUrl,
            cdkeyAuthToken,
            cdkeyTimeoutMs,
        };
    }

}
