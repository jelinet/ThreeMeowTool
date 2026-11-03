#include "Hooks_Misc.h"
#include "HookMacros.h"
#include "Utils/HookSupport/VehCommon.h"
#include "dllmain.h"
#include "OSTPlatform/include/SteamCredentialStore.h"
#include "Utils/SteamMetadata/CDKeyReporter.h"
#include "Utils/Config/Config.h"

namespace {
    // ── Resolve-only functions ─────────────────────────────────────
    RESOLVE_FUNC(CUtlBufferEnsureCapacity, void*, CUtlBuffer* pCUtlBuffer, uint32 newCapacity);

    // ── VEH-captured functions (one-shot int3) ───────────────────────────────
    // On int3 hit, ctx->Rcx is stored to the named output variable.
    CAPTURE_THIS_FUNC(GetAppIDForCurrentPipe, AppId_t,      g_steamEngine,    void*);
    CAPTURE_THIS_FUNC(GetAppDataFromAppInfo,  int64,        g_pCAppInfoCache, void*, AppId_t, const char*, uint8*, int32);

    // Assumes one game at a time.  Set by SpawnProcess VEH when -onlinefix
    // is detected; cleared when a non-onlinefix game launches.
    AppId_t   g_OnlineFixRealAppId;
    // 游戏开始走 SteamNetworkingSockets 之后置位，见 GetAppID 处理器。
    bool      g_NetworkingSocketsActive;
    // 本次启动是否用 -realappid 关掉 appid 翻转，见 ShouldReportOnlineFixAppId。
    bool      g_SuppressAppIdFlip;
    std::unordered_map<AppId_t, std::string> g_GameNameCache;


    // ── SpawnProcess interception ────────────────────────────────────────────
    // CUser_SpawnProcess(pCUser, pExePath, pCommandLine, pWorkingDir,
    //                    pGameID, ...)
    // arg1=pCUser, arg2=pExePath, arg3=pCommandLine, arg4=pWorkingDir
    // arg5=pGameID (CGameID*; low 24 bits = AppId)
    static void OnSpawnProcessHit(OSTPlatform::Trap::Context& ctx, const VehCommon::Int3Site& /*site*/) {
        CGameID* pGameID = VehCommon::GetArg<CGameID*>(ctx, 5);
        AppId_t appId = static_cast<AppId_t>(pGameID->AppID(true));
        const char* cmdLine = VehCommon::GetArg<const char*>(ctx, 3);

                // appId 是值类型，按值捕获；千万不要引用捕获 ctx 或它的参数——  
        // handler 返回后 ctx 就失效了  
        //std::thread([appId] {  
        namespace CS = OSTPlatform::SteamCredentialStore;

        // ── 当前登录账号的 steamid64 ──
        uint64_t currentSteamId = 0;
        uint32_t accountId = 0;
        std::wstring universe;
        if (CS::GetActiveUser(accountId, universe) == CS::Status::Ok) {
            // universe 基本是 "public"(=1)，steamid64 = universe<<56 | 1<<52 | 1<<32 | accountId
            // public 下直接加常量即可，得到 76561198401240766 这样的值
            currentSteamId = 0x110000100000000ull + accountId;
        }

        //读取注册表，判断游戏
        bool isDenuvo = false;
        bool isExpiredDenuvo = false;
        bool isSteamDrm = false;
        std::string cdkey;
        const auto status = CS::GetDenuvoFlag(appId, isDenuvo, isExpiredDenuvo, isSteamDrm, cdkey);
        if (status != CS::Status::Ok) {
            LOG_MISC_INFO("OnSpawnProcessHit read Denuvo flag failed ({})", CS::ToString(status));
        } else {
            LOG_MISC_INFO("OnSpawnProcessHit read Denuvo flag for appid={} isDenuvo={} isExpiredDenuvo={} isSteamDrm={} cdkey={}",
                          appId, isDenuvo, isExpiredDenuvo, isSteamDrm, cdkey);
            // 兜底：三个标记都没写过（正常在 /cdkeycheck 成功后由 WriteRegistry 写好），问一次 /appinfo。
            // 成功会写进注册表，下次启动就不再请求；失败按三个 false 处理，下次启动再试。
            if (!CS::HasDrmFlags(appId)) {
                const bool got = CDKeyReporter::FetchAppInfo(appId, isDenuvo, isExpiredDenuvo, isSteamDrm);
                LOG_MISC_INFO("OnSpawnProcessHit: appid={} no drm flags in registry, appinfo={} isDenuvo={} isExpiredDenuvo={} isSteamDrm={}",
                              appId, got, isDenuvo, isExpiredDenuvo, isSteamDrm);
            }
            //加密的appid，缺 AppTicket 时用激活时记下的 cdkey 去服务端换票
            if (isDenuvo) {
                LOG_MISC_INFO("OnSpawnProcessHit: appid={} is Denuvo protected", appId);
                // std::vector<uint8_t> appticket;
                // const CS::Status s1 = CS::GetAppTicket(appId, appticket);
                // const bool hasAppTicket = (s1 == CS::Status::Ok && !appticket.empty());

                // std::vector<uint8_t> eticket;
                // const CS::Status s2 = CS::GetETicket(appId, eticket);
                // const bool hasETicket = (s2 == CS::Status::Ok && !eticket.empty());
                // // fmt 不能直接格式化 std::vector，用 spdlog::to_hex（Log.h 已引入 bin_to_hex.h）；
                // // {:snp} = 不加空格、不分行、不带偏移，打成一整串十六进制。
                // LOG_MISC_INFO("OnSpawnProcessHit: get registry appid={} appticket({} bytes)={:snp} eticket({} bytes)={:snp} hasAppTicket={} hasETicket={}",
                //     appId, appticket.size(), spdlog::to_hex(appticket), eticket.size(), spdlog::to_hex(eticket),
                //     hasAppTicket, hasETicket);
                // 不再看注册表里有没有票，每次都调接口；接口值和注册表不一样才整套重写，
                // 比较和写入都在 FetchTicketsByCdkey 里（2026-10-25 和使用者确认）。
                // 代价：每次启动 Denuvo 游戏都会同步请求一次，服务端慢时会卡启动。
                if (cdkey.empty()) {
                    LOG_MISC_WARN("OnSpawnProcessHit: appid={} has no CDKey in registry, skip ticket fetch", appId);
                } else {
                    bool ticketsFetched = CDKeyReporter::FetchTicketsByCdkey(appId, cdkey, currentSteamId);
                    LOG_MISC_INFO("OnSpawnProcessHit: ticket fetch appid={}, cdkey={}, currentSteamId={}, ticketsFetched={}",
                         appId, cdkey, currentSteamId, ticketsFetched);
                }
            }else if (isExpiredDenuvo) {
                LOG_MISC_INFO("OnSpawnProcessHit: appid={} is expired Denuvo protected", appId);
            }else if (isSteamDrm) {
                LOG_MISC_INFO("OnSpawnProcessHit: appid={} is Steam DRM protected", appId);
                std::vector<uint8_t> appticket;
                const CS::Status s1 = CS::GetAppTicket(appId, appticket);
                const bool hasAppTicket = (s1 == CS::Status::Ok && !appticket.empty());

                // 离过期不到 8 小时就提前换票（2026-10-24 和使用者确认）；没有过期时间（旧数据）也换。
                constexpr int64_t kRefreshBeforeExpirySec = 8 * 60 * 60;
                uint64_t expiresAt = 0;
                const bool hasExpTime = CS::GetAppTicketExpTime(appId, expiresAt) == CS::Status::Ok;
                const int64_t now = static_cast<int64_t>(std::time(nullptr));
                const int64_t remaining = hasExpTime ? static_cast<int64_t>(expiresAt) - now : 0;
                const bool needFetch = !hasAppTicket || !hasExpTime || remaining < kRefreshBeforeExpirySec;

                LOG_MISC_INFO("OnSpawnProcessHit: SteamDrm appid={} hasAppTicket={} ({} bytes) expiresAt={} remaining={}s needFetch={}",
                              appId, hasAppTicket, appticket.size(), expiresAt, remaining, needFetch);
                if (needFetch) {
                    const bool fetched = CDKeyReporter::FetchAppTicket(appId, std::string(LuaDir));
                    LOG_MISC_INFO("OnSpawnProcessHit: appticket fetch appid={} fetched={}", appId, fetched);
                }
            }
        }
        // 每次命中均记录启动参数，用于区分 hook 未触发与启动参数缺失两种情况。
        LOG_MISC_DEBUG("SpawnProcess hit: appid {} cmd=\"{}\"", appId, cmdLine ? cmdLine : "<null>");

        // 只看启动参数，不再要求 appid 在 Lua 名单里：正版玩家加 -onlinefix
        // 联机同样要生效，解锁名单不该决定联机开关。
        if (cmdLine && strstr(cmdLine, "-onlinefix"))
        {
            g_OnlineFixRealAppId = appId;
            g_NetworkingSocketsActive = false;
            // 逐局关闭 appid 翻转：启动期就要读自己 appid 的游戏会卡在黑屏，
            // 这个调用本身分不出游戏意图，只能交给用户按局指定。
            g_SuppressAppIdFlip = strstr(cmdLine, "-realappid") != nullptr;
            pGameID->SetAppID(kOnlineFixAppId);
            LOG_MISC_INFO("SpawnProcess: appid {} -> {}, realappid={}, cmd=\"{}\"",
                          appId, kOnlineFixAppId, g_SuppressAppIdFlip, cmdLine);
        } else {
            g_OnlineFixRealAppId = 0;
            g_SuppressAppIdFlip = false;
        }
    }

    // ── SteamController_OptedInMask ──────────────────────────────────────────
    // Called by CUser_BuildSpawnEnvBlock with pGameID's appid to
    // compute EnableConfiguratorSupport and the SDL_* env vars.
    // With 480 the spawned game inherits Spacewar's Steam Input
    // opt-in and gameoverlayrenderer hijacks the XInput stream.
    HOOK_FUNC(OptedInMask, int64,void* pThis, AppId_t appId)
    {
        if (appId == kOnlineFixAppId && g_OnlineFixRealAppId) {
            LOG_MISC_INFO("OptedInMask: appid {} -> {}",appId, g_OnlineFixRealAppId);
            appId = g_OnlineFixRealAppId;
        }
        return oOptedInMask(pThis, appId);
    }

    // ── CUser_BuildSpawnEnvBlock ─────────────────────────────────────────────
    // pOverlayCGameID drives SteamOverlayGameId, which the in-game
    // overlay reads for screenshot tags, community URLs, and asset
    // selection.  pCGameID drives SteamGameId / SteamAppId; leave it
    // at 480 so the in-game ownership bypass holds.
    HOOK_FUNC(BuildSpawnEnvBlock, int64,
              void* pThis, CGameID* pCGameID, void* a3, void* env,
              CGameID* pOverlayCGameID, void* a6, int a7,
              void* a8, void* a9, unsigned int a10, char a11)
    {
        if (g_OnlineFixRealAppId && pOverlayCGameID
            && pOverlayCGameID->AppID(true) == kOnlineFixAppId) 
        {
            LOG_MISC_INFO("BuildSpawnEnvBlock: SetAppID in OverlayCGameID {} -> {}",
                          pOverlayCGameID->AppID(true), g_OnlineFixRealAppId);
            pOverlayCGameID->SetAppID(g_OnlineFixRealAppId);
        }
        return oBuildSpawnEnvBlock(pThis, pCGameID, a3, env,
                                    pOverlayCGameID, a6, a7,
                                    a8, a9, a10, a11);
    }

    // CAppInfoCache::GetOrAddAppData
    // The injected package keeps Lua-provided ids in PackageInfo::AppIdVec.
    // Some of those ids can actually be depot ids, but we cannot trust the
    // Lua config to classify app ids and depot ids for us. In offline mode,
    // depot ids usually have only placeholder appinfo data. That blocks
    // CClientAppManager_ProcessPendingLicenseUpdates, because it waits for
    // every AppIdVec entry to have resolved appinfo unless the entry has been
    // marked as a known-unknown id by the PICS path. For injected ids that
    // still have placeholder appinfo, set skip_flag so Steam treats them like
    // PICS unknown_appids instead of keeping the license update pending.
    HOOK_FUNC(GetOrAddAppData,CAppData*,void* pCache, AppId_t appId,bool bCreate)
    {
        CAppData* pData = oGetOrAddAppData(pCache, appId, bCreate);
        // LOG_MISC_TRACE("GetOrAddAppData: appId={} bCreate={} -> pData={}", appId, bCreate, pData ? pData->DebugString() : "null");
        // TODO: find a more robust way
        if (LuaConfig::HasDepot(appId, false) && pData && !bCreate && pData->IsUnresolvedAppInfo()) {
            LOG_MISC_DEBUG("GetOrAddAppData: Marking appId {} as skip_flag=true to bypass license update blocking", appId);
            pData->bSkipFlag = true;
        }
        return pData;
    }
}

namespace Hooks_Misc {
    void Install() {
        RESOLVE_C(CUtlBufferEnsureCapacity);

        ARM_CAPTURE_C(GetAppIDForCurrentPipe);
        ARM_CAPTURE_C(GetAppDataFromAppInfo);

        ARM_INT3_C(SpawnProcess, true, &OnSpawnProcessHit, nullptr);

        HOOK_BEGIN();
        INSTALL_HOOK_C(BuildSpawnEnvBlock);
        INSTALL_HOOK_C(OptedInMask);
        // INSTALL_HOOK_C(GetOrAddAppData);
        HOOK_END();
    }

    void Uninstall() {
        UNHOOK_BEGIN();
        UNINSTALL_HOOK(BuildSpawnEnvBlock);
        UNINSTALL_HOOK(OptedInMask);
        // UNINSTALL_HOOK(GetOrAddAppData);
        UNHOOK_END();
    }

    AppId_t GetAppIDForCurrentPipeWrap() {
        if (!CAPTURE_READY(GetAppIDForCurrentPipe)) {
            LOG_MISC_WARN("GetAppIDForCurrentPipeWrap called before capture — returning 0");
            return 0;
        }
        auto appid = oGetAppIDForCurrentPipe(g_steamEngine);
        if (!appid) {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId=0(Not GamePipe)");
        } else {
            LOG_MISC_TRACE("GetAppIDForCurrentPipeWrap: AppId={}", appid);
        }
        return appid;
    }

    
    AppId_t ResolveAppId() {
        if (g_OnlineFixRealAppId) return g_OnlineFixRealAppId;
        return GetAppIDForCurrentPipeWrap();
    }

    bool IsOnlineFixActive() {
        return g_OnlineFixRealAppId != 0;
    }

    void NotifyNetworkingSocketsUsed() {
        if (g_OnlineFixRealAppId && !g_NetworkingSocketsActive) {
            g_NetworkingSocketsActive = true;
            LOG_MISC_INFO("NetworkingSockets active: GetAppID now reports {}",
                          g_SuppressAppIdFlip ? "real appid (-realappid)" : "480 for cert match");
        }
    }

    bool ShouldReportOnlineFixAppId() {
        // 翻转的用途是让 P2P socket 的 appid 与 480 会话证书对上，部分游戏靠它联机。
        // 但它一旦触发，本进程余下生命周期里每次询问都答 480；另一些游戏在启动期
        // 问同一句话拿到 480 就会卡死或黑屏。两侧都有游戏需要，而这个调用本身
        // 分不出对方是哪一类，于是用 -realappid 逐局退出。
        if (g_SuppressAppIdFlip) return false;
        return g_OnlineFixRealAppId != 0 && g_NetworkingSocketsActive;
    }
    
    bool EnsureBufferCapacity(CUtlBuffer* pWrite, uint32 newCapacity,bool updatePut)
    {
        if (oCUtlBufferEnsureCapacity) {
            LOG_MISC_DEBUG("Before ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            oCUtlBufferEnsureCapacity(pWrite, newCapacity);
            LOG_MISC_DEBUG("After ensuring CUtlBuffer capacity: {}", pWrite->DebugString());
            if(updatePut) pWrite->m_Put = newCapacity;
            return true;
        }
        LOG_MISC_WARN("EnsureBufferCapacity: oCUtlBufferEnsureCapacity not resolved");
        return false;
    }

    // ── Game name ────────────────────────────────────────────────
    std::string GetGameNameByAppID(AppId_t appId)
    {
        auto it = g_GameNameCache.find(appId);
        if (it != g_GameNameCache.end()) return it->second;

        std::string name;

        if (CAPTURE_READY(GetAppDataFromAppInfo)) {
            char buf[256] = {};
            // "common/name" triggers auto-localization: the function detects
            // prefix "common" (keyType=2) + key "name", then tries
            // "name_localized/<current_lang>" before falling back to "name".
            // Returns strlen+1 on success, -1 on failure.
            int64 len = oGetAppDataFromAppInfo(g_pCAppInfoCache, appId, "common/name",
                reinterpret_cast<uint8*>(buf), sizeof(buf));
            if (len > 1)
                name.assign(buf, static_cast<size_t>(len - 1));
        }

        LOG_MISC_DEBUG("GetGameNameByAppID({}): {}", appId, name);
        g_GameNameCache[appId] = name;
        return name;
    }

}
