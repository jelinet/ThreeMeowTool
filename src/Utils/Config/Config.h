#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Config {

    enum class LogLevel { Trace, Debug, Info, Warn, Error };

    struct ManifestTimeouts {
        uint32_t resolve = 5000;
        uint32_t connect = 5000;
        uint32_t send    = 10000;
        uint32_t recv    = 10000;
    };

    struct InjectionSettings {
        bool enabled = false;
        std::string libraryX86;
        std::string libraryX64;
    };

    struct CloudSettings {
        bool enabled = false;
        std::string library;
    };

    // baseUrl / authToken 来自注册表 HKLM\SOFTWARE\OpenSteamTool\CDKey（见 Config.cpp 的 ReadCdkeyRegistry），
    // timeoutMs 来自 toml [cdkey]。
    struct CdkeySettings {
        std::string baseUrl;            
        std::string authToken;          
        uint32_t    timeoutMs = 2000;
    };

    struct LoadResult {
        bool applied = false;
        bool luaPathsChanged = false;
    };

    LoadResult Load(const std::string& configPath);

    ManifestTimeouts GetManifestTimeouts();
    LogLevel GetLogLevel();
    std::string GetLogDir();
    std::vector<std::string> GetLuaPaths();
    std::vector<std::string> GetRemoteUrlTemplates();
    // std::string GetRemoteOrder();
    InjectionSettings GetInjectionSettings();
    CloudSettings GetCloudSettings();
    bool GetStatsEnableApi();
    CdkeySettings GetCdkeySettings();

    // [presence] — friend broadcast mode: "spacewar" (default) or "none".
    // Anything other than "none" keeps the current broadcast behavior.
    bool GetPresenceBroadcastEnabled();

    // [manifest] — provider selection lives in ManifestClient (table-driven).
    inline uint32_t manifestTimeoutResolve = 5000;
    inline uint32_t manifestTimeoutConnect = 5000;
    inline uint32_t manifestTimeoutSend    = 10000;
    inline uint32_t manifestTimeoutRecv    = 10000;
    // 顺位回退开关：关闭时仅请求首选源。
    inline bool manifestFailover = true;

    // [log]
    inline LogLevel logLevel = LogLevel::Debug;

    // derived from configPath: <steam>/opensteamtool/
    inline std::string logDir;

    // [lua]
    inline std::vector<std::string> luaPaths;


    // [remote] — one or more mirror templates, tried in order. Empty = built-in defaults.
    inline std::vector<std::string> remoteUrlTemplates;
    // // 默认 gh-proxy 镜像优先、GitHub 直连兜底；配成 "github-first" 切顺序；
    // // 旧值 "jsdelivr-first" 继续认，等同 gh-proxy-first
    // inline std::string remoteOrder = "gh-proxy-first";

    // [stats]
    inline bool statsEnableApi = true;

    // [presence] — "spacewar" shows the real game name to friends (default),
    // "none" skips the name broadcast patches.
    inline std::string presenceDisplay = "spacewar";

    // [inject] - optional library injection into game processes.
    inline bool injectEnabled = false;
    inline std::string injectLibraryX86;
    inline std::string injectLibraryX64;

    // [cloud] - optional Steam Cloud save redirection via CloudRedirect.
    inline bool cloudEnabled = false;
    inline std::string cloudLibrary;

    // [cdkey]
    inline std::string cdkeyBaseUrl;
    inline std::string cdkeyAuthToken;
    inline uint32_t    cdkeyTimeoutMs = 5000;

}
