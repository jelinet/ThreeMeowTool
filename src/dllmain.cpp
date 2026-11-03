#include "dllmain.h"
#include "Hook/HookManager.h"
#include "Hook/Hooks_Package.h"
#include "Hook/Hooks_SteamUI.h"
#include "Utils/Config/ConfigFileWatcher.h"
#include "Utils/Config/LuaFileWatcher.h"
#include "Utils/CloudRedirect/CloudRedirectHost.h"
#include "Utils/SteamMetadata/IPCLoader.h"
#include "Utils/SteamMetadata/PatternLoader.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"
#include "OSTPlatform/include/DynamicLibrary.h"
#include "OSTPlatform/include/Thread.h"

#include <chrono>
#include <filesystem>
#include <thread>
#include <windows.h>

namespace {

// Diversion 影子模块的文件操作：全部跑在 InitThread worker 线程，绝不在 loader lock 下。
constexpr int kDiversionCopyRetries = 3;
constexpr std::chrono::milliseconds kDiversionCopyRetryDelay{50};

// 我们进进程时 steamclient64 是否已在内存，决定首载抢劫有没有机会：
// 在 = 来晚了，Steam 不会再 Load 第二次；不在 = 首载还没发生。
// GetModuleHandle 只是读 PEB，loader lock 下调安全；建线程自带 happens-before，直接读就行。
bool g_steamClientMappedAtAttach = false;

bool IsDiversionUpToDate() {
    WIN32_FILE_ATTRIBUTE_DATA origAttr{}, divAttr{};
    const bool origExists =
        GetFileAttributesExA(SteamclientPath, GetFileExInfoStandard, &origAttr) != 0;
    const bool divExists =
        GetFileAttributesExA(DiversionPath, GetFileExInfoStandard, &divAttr) != 0;
    if (!origExists || !divExists) return false;
    return origAttr.nFileSizeHigh == divAttr.nFileSizeHigh &&
           origAttr.nFileSizeLow == divAttr.nFileSizeLow &&
           origAttr.ftLastWriteTime.dwLowDateTime == divAttr.ftLastWriteTime.dwLowDateTime &&
           origAttr.ftLastWriteTime.dwHighDateTime == divAttr.ftLastWriteTime.dwHighDateTime;
}

bool CopySteamClientToDiversion() {
    std::error_code ec;
    std::filesystem::path diversionFsPath(DiversionPath);
    std::filesystem::create_directories(diversionFsPath.parent_path(), ec);
    if (ec) {
        LOG_WARN("Diversion: failed to create directory for {} ({})", DiversionPath, ec.message());
        return false;
    }
    // 先拷到临时文件再原子替换：两个 Steam 进程同时启动时，直接写同一目标
    // 会产生撕裂副本；MoveFileEx 替换是原子的，读到的要么是旧完整版要么是新完整版。
    char tmpPath[kRuntimePathCapacity] = {};
    sprintf_s(tmpPath, "%s.tmp", DiversionPath);
    // 旧 Steam 进程可能还占着句柄：只读属性先清掉，否则 CopyFile 必败。
    const DWORD attrs = GetFileAttributesA(tmpPath);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
        SetFileAttributesA(tmpPath, FILE_ATTRIBUTE_NORMAL);
    }
    for (int attempt = 1; attempt <= kDiversionCopyRetries; ++attempt) {
        if (CopyFileA(SteamclientPath, tmpPath, FALSE) &&
            MoveFileExA(tmpPath, DiversionPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            LOG_INFO("Diversion: cloned steamclient64.dll -> {}", DiversionPath);
            return true;
        }
        const DWORD gle = GetLastError();
        // 只有共享冲突/拒绝访问值得重试；路径错误等直接放弃，不烧时间。
        if (gle != ERROR_SHARING_VIOLATION && gle != ERROR_ACCESS_DENIED) {
            LOG_WARN("Diversion: CopyFile failed, not retryable (err={})", gle);
            break;
        }
        if (attempt < kDiversionCopyRetries) {
            std::this_thread::sleep_for(kDiversionCopyRetryDelay);
        } else {
            LOG_WARN("Diversion: CopyFile failed after {} attempts (err={})",
                     kDiversionCopyRetries, gle);
        }
    }
    return false;
}

} // namespace

// 回退到原版 steamclient：B2（劫持没装上）和超时看门狗（Steam 不来换）共用。
// clientHooksArmed：client hook 是否已装在副本上（看门狗场景 true，需先卸再装；
// B2 场景 false，hook 还没装，直接换模块即可）。
// 成功返回 true；原版都加载失败返回 false（调用方按致命处理）。
static bool FallbackToOriginalSteamClient(bool clientHooksArmed) {
    if (clientHooksArmed) SteamClient::CoreUnhook();
    // 注意：绝不 FreeLibrary diversion 副本！cloud_redirect 初始化时经
    // GetModuleHandle 拿到副本句柄做地址解析 + vtable patch，存的全是绝对地址；
    // 一旦卸载，下一次 stats/cloud RPC 就踩野指针崩溃，所以副本只废弃不卸载。
    // 副本废弃但保持映射（多一个模块映射的代价），hook 已卸、谁也不会再用它，安全。
    // client_hModule 直接指向原版，后续劫持分发与查询重定向全走原版，全程一致。
    // 注意：回退后整个会话是原版世界，首载抢劫必须永久 bypass，不然之后再有人
    // LoadLibrary(steamclient) 会拿到副本，两套 client 并存状态错乱。
    // 这里只开不开：连 fallback 自己的这次 Load 也一并放行。
    Hooks_SteamUI::SetFirstLoadRedirectBypass(true);
    client_hModule = OSTPlatform::DynamicLibrary::Load(SteamclientPath);
    g_IsDiversionActive.store(false);
    if (!client_hModule) {
        LOG_ERROR("Diversion fallback: Load steamclient64.dll failed: {} (err={})",
                  SteamclientPath, OSTPlatform::DynamicLibrary::GetLastErrorCode());
        return false;
    }
    // PatternLoader 的 map 按模块句柄缓存，换模块后必须重 Load 一次。
    PatternLoader::Load(client_hModule, SteamclientPath, "steamclient");
    if (clientHooksArmed) {
        SteamClient::CoreHook();
        PatternLoader::ReportMissingFunctions();
    }
    // hook 晚装：Steam 在生效前已查完 ownership，之后不再主动重查。
    // 置自举标志，下一次 CheckAppOwnership 用已就位的 CUser 强制刷一次，
    // 第二波查询到来时注入完成。正常路径从不置位，零影响。
    Hooks_Package::RequestRequeryOnce();
    LOG_WARN("Diversion: fallback complete, hooks now on original steamclient64 — "
             "unlock keeps working, isolation disabled");
    return true;
}

// 超时回退看门狗：init 完成后 15s 内 Steam 还没换到副本上，基本可判定它在用
// 启动时加载的原版（正常机器 1 秒内就换），副本上的 hook 全打空（解锁静默全灭）。
// 此时搬回原版保解锁。误回退的代价只是丢隔离（= 1.5.2.1 行为，已验证可用）。
// 睡眠分片：进程退出时最多 5s 内响应，不在已卸载的代码里醒来。
constexpr auto kDiversionAdoptTimeout = std::chrono::seconds{15};
constexpr auto kWatchdogSlice = std::chrono::seconds{5};
static_assert(kDiversionAdoptTimeout >= kWatchdogSlice,
              "watchdog slice must divide the adopt timeout (else zero slices = instant fallback)");

static uint32_t DiversionWatchdog() {
    const int slices = static_cast<int>(kDiversionAdoptTimeout / kWatchdogSlice);
    for (int i = 0; i < slices; ++i) {
        std::this_thread::sleep_for(kWatchdogSlice);
        // 进程正在退出/已卸载：直接结束，不碰任何东西。
        if (!g_HooksInstalled.load()) return 0;
    }
    if (!g_IsDiversionActive.load() || g_DiversionAdopted.load()) return 0;
    LOG_WARN("Diversion: Steam did not adopt the diversion module within {}s "
             "(still using startup-loaded original), falling back to original steamclient64",
             static_cast<int>(kDiversionAdoptTimeout.count()));
    if (!FallbackToOriginalSteamClient(true)) return 1;
    return 0;
}

// prepare key runtime paths.
bool InitializeSteamComponents()
{
    // Steam 根目录以宿主 exe 为准，不用 CWD：经外部工具拉起 steam.exe 时 CWD
    // 是继承来的工具目录，用 CWD 会导致 steamclient64.dll 定位失败、整个 init
    // 静默全灭（零 hook、解锁全灭）。steamclient64.dll 必定与 steam.exe 同目录，
    // exe 路径才是唯一可信的锚点。
    const std::filesystem::path exePath = OSTPlatform::DynamicLibrary::GetMainExecutablePath();
    const std::string exeName = exePath.filename().string();
    if (exeName.empty() || _stricmp(exeName.c_str(), "steam.exe") != 0) {
        LOG_INFO("InitializeSteamComponents: host is not steam.exe ({}), skipping",
                 exeName.empty() ? "(unknown)" : exeName);
        return false;
    }
    const std::string steamInstallPath = exePath.parent_path().string();
    if (steamInstallPath.empty()) {
        return false;
    }
    LOG_INFO("Steam install path: {} (host {})", steamInstallPath, exePath.string());
    sprintf_s(SteamInstallPath, kRuntimePathCapacity, "%s", steamInstallPath.c_str());
    sprintf_s(SteamclientPath, kRuntimePathCapacity, "%s\\steamclient64.dll",  SteamInstallPath);
    sprintf_s(SteamUIPath,     kRuntimePathCapacity, "%s\\steamui.dll",        SteamInstallPath);
    sprintf_s(DiversionPath,   kRuntimePathCapacity, "%s\\bin\\diversion64.dll", SteamInstallPath);
    sprintf_s(LuaDir,          kRuntimePathCapacity, "%s\\config\\lua",        SteamInstallPath);
    sprintf_s(ConfigPath,      kRuntimePathCapacity, "%s\\opensteamtool.toml", SteamInstallPath);
    
    // Diversion 影子模块：所有 hook 只打在 steamclient64.dll 的完整副本上，
    // 原版模块保持 100% 干净，Denuvo/RE 引擎的完整性检查才能通过。
    // 副本加载失败很可能是 Steam 自更新中途拷出的撕裂文件，删掉重拷一次再试；
    // 还不行才回退原版并大声告警——静默回退等于安静裸奔。
    client_hModule = nullptr;
    // 隔离总开关：只有抢在 steamclient 首载之前进入进程，首载抢劫才有窗口可抢。
    // 到达时若 steamclient64 已在内存（dwmapi 经 vgui2_s 晚注），继续造副本也换不上，
    // 看门狗只会空等超时再回退，白拷一份几十 MB 的副本。这种晚注场景直接不造副本、
    // 不装首载重定向、不起看门狗，全程用原版。
    const bool diversionEnabled = !g_steamClientMappedAtAttach;
    // 只有"确认最新"或"刚拷成功"的副本才值得信任；拷都拷不出来就别碰旧文件，
    // 直接回退原版（陈旧副本不可信）。
    bool diversionFileUsable = false;
    if (diversionEnabled) {
        diversionFileUsable = IsDiversionUpToDate();
        if (!diversionFileUsable) {
            diversionFileUsable = CopySteamClientToDiversion();
        } else {
            LOG_DEBUG("Diversion module is already up to date ({}), skipping copy", DiversionPath);
        }
    }
    if (diversionFileUsable) {
        client_hModule = OSTPlatform::DynamicLibrary::Load(DiversionPath);
    }
    if (!client_hModule && diversionFileUsable) {
        LOG_WARN("Load diversion module failed (path={}, err={}), deleting possibly torn copy and cloning once more",
                 DiversionPath, OSTPlatform::DynamicLibrary::GetLastErrorCode());
        DeleteFileA(DiversionPath);
        if (CopySteamClientToDiversion()) {
            client_hModule = OSTPlatform::DynamicLibrary::Load(DiversionPath);
        }
    }
    if (client_hModule) {
        g_IsDiversionActive.store(true);
        LOG_INFO("Loaded diversion module from {}", DiversionPath);
    } else {
        g_IsDiversionActive.store(false);
        client_hModule = OSTPlatform::DynamicLibrary::Load(SteamclientPath);
        if (!client_hModule) {
            LOG_ERROR("Load steamclient64.dll failed: {} (err={})",
                      SteamclientPath, OSTPlatform::DynamicLibrary::GetLastErrorCode());
            return false;
        }
        if (diversionEnabled) {
            LOG_WARN("Diversion inactive, loaded fallback steamclient64.dll from {} — hooks run on the original module, integrity-checked games may crash",
                     SteamclientPath);
        } else {
            LOG_INFO("Diversion skipped (arrived after steamclient64 first load), using original steamclient64.dll from {}",
                     SteamclientPath);
        }
    }
    
    ui_hModule = OSTPlatform::DynamicLibrary::Load(SteamUIPath);
    if(!ui_hModule) {
        LOG_ERROR("Load failed for steamui.dll: err={}", OSTPlatform::DynamicLibrary::GetLastErrorCode());
        return false;
    }
    return true;
}

// All initialisation that touches the filesystem, loads modules, scans
// memory, or installs detours runs here on a worker thread — we MUST NOT do
// any of that from inside DllMain (loader lock).
static uint32_t InitThread(OSTPlatform::DynamicLibrary::ModuleHandle selfModule) {
    Log::Init(selfModule);
    LOG_INFO("OpenSteamTool init thread started");
    LOG_INFO("OpenSteamTool attach: steamclient64 already mapped = {} ({})",
             g_steamClientMappedAtAttach,
             g_steamClientMappedAtAttach
                 ? "we arrived late, first-load redirect cannot work"
                 : "first load not yet happened, FirstLoadRedirect may catch it");

    if (!InitializeSteamComponents()) {
        LOG_ERROR("InitializeSteamComponents failed");
        return 1;
    }

    // 首载抢劫即刻武装：只依赖 kernel32，与 pattern/SteamUI hook 无依赖，
    // 越早装上抢到 Steam 主线程首次 LoadLibrary(steamclient) 的窗口越大。
    if (g_IsDiversionActive.load())
        Hooks_SteamUI::InstallFirstLoadRedirect();

    Config::Load(ConfigPath);
    Log::InitModules();
    Log::InstallPlatformLogSink();
    SteamDiagnostics::Initialize(SteamclientPath, SteamUIPath);

    // Load pattern files for steamclient64.dll and steamui.dll.
    // Each call computes the SHA-256 of the DLL on disk, checks the local
    // cache, and downloads from GitHub if needed.  Both calls are synchronous
    // but run on this worker thread, never under the loader lock.
    PatternLoader::Load(ui_hModule, SteamUIPath, "steamui");
    PatternLoader::Load(client_hModule, SteamclientPath, "steamclient");

    // SteamUI hook 先装：LoadModuleWithPath 劫持必须在 Steam 自己加载
    // steamclient 之前就位，它内部会等 g_HooksInstalled 屏障再放行。
    // （首载抢劫已在 InitializeSteamComponents 后就位，见上。）
    SteamUI::CoreHook();

    // 两条换机路径任一可用就不回退：LoadModuleWithPath 劫持（老路径）或
    // 首载抢劫（1791 路径）；两条都没了影子模块才是没人用的摆设，必须
    // 换回原版再装 client hook，否则解锁静默全灭。
    if (g_IsDiversionActive.load() && !Hooks_SteamUI::IsDiversionRedirectArmed() &&
        !Hooks_SteamUI::IsFirstLoadRedirectArmed()) {
        LOG_WARN("Diversion redirect unavailable (LoadModuleWithPath pattern missing), "
                 "falling back to original steamclient64 — unlock keeps working, isolation disabled");
        if (!FallbackToOriginalSteamClient(false)) {
            LOG_ERROR("Fallback Load steamclient64.dll failed");
            return 1;
        }
    }

    // IPC method metadata (funcHash, fencepost, argc, ...)
    IPCLoader::Load(SteamclientPath);

    std::vector<std::string> watchDirs = Config::GetLuaPaths();
    watchDirs.push_back(std::string(LuaDir));
    for (const auto& dir : watchDirs)
        LuaConfig::ParseDirectory(dir);

    LuaFileWatcher::Start(watchDirs);
    ConfigFileWatcher::Start(ConfigPath, LuaDir);

    SteamClient::CoreHook();

    // Surface any functions that FindPattern() could not locate.
    PatternLoader::ReportMissingFunctions();

    // Optional Steam Cloud save redirection (CloudRedirect). No-op unless
    // [cloud].enabled is set and cloud_redirect.dll is present.
    CloudRedirectHost::Initialize(SteamInstallPath);

    g_HooksInstalled.store(true);
    LOG_INFO("OpenSteamTool init complete ({})",
             g_IsDiversionActive.load() ? "Diversion active" : "Diversion bypassed, using original steamclient64");
    // 超时回退看门狗：只在隔离启用时才有事可做，直连原版时不启线程。
    if (g_IsDiversionActive.load())
        OSTPlatform::Thread::StartDetached([] { return DiversionWatchdog(); });
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        g_steamClientMappedAtAttach = (GetModuleHandleW(L"steamclient64.dll") != nullptr);
        // Hand off all real work to a worker thread to avoid running file I/O,
        // module loading and detour transactions under the loader lock.
        OSTPlatform::Thread::StartDetached([module = reinterpret_cast<OSTPlatform::DynamicLibrary::ModuleHandle>(hModule)] {
            return InitThread(module);
        });
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        g_HooksInstalled.store(false);
        g_IsDiversionActive.store(false);
        g_DiversionAdopted.store(false);
        ConfigFileWatcher::Stop();
        LuaFileWatcher::Stop();
        SteamUI::CoreUnhook();
        SteamClient::CoreUnhook();
        CloudRedirectHost::Shutdown();
    }

    return TRUE;
}
