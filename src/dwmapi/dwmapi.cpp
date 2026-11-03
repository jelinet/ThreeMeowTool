// dwmapi.dll HiJack Project - loader-stage agent (反作弊友好入口)。
//
// 职责与 version.dll 代理一致：把 OpenSteamTool.dll 带进 steam.exe 进程。
// 差别在加载路径——version 是 steam.exe 的静态导入，随加载器最先进入；
// dwmapi 走 bin\vgui2_s.dll 的静态导入，Steam 起界面时被连带加载。
//
// 本模块处在 Steam 的关键加载路径上：导出的每个函数都必须原样转发回系统
// dwmapi，否则依赖它的模块（vgui2_s 调用 DwmExtendFrameIntoClientArea /
// DwmSetWindowAttribute）会缺符号、整个模块加载失败，Steam 直接起不来
// （表现为 VGUI_Setup failed）。
//
// 为什么不用 MSVC 的 /EXPORT:名字=DWMAPI.名字 转发器：转发器记录的目标模块名
// "DWMAPI" 会被加载器解析成模块 dwmapi.dll，而本模块自己就叫这个名字——
// 命中应用目录里的自己形成自环，vgui2_s 必然加载失败。所以这里改成运行期
// GetProcAddress 取系统 dwmapi 的真实地址，再逐个手动转发。

#include <windows.h>

// 系统真身必须以绝对路径绑定：按名 LoadLibrary("dwmapi.dll") 会命中本模块自己。
static HMODULE g_hRealDwmapi = nullptr;

// 系统 dwmapi 各导出函数的真实地址。缺任何一项都只在调用处兜底返回失败，
// 绝不让转发路径抛异常或崩掉宿主——本模块是 Steam 静态导入链的一环。
// 故意不导出 DllCanUnloadNow / DllGetClassObject：dwmapi 的 COM 对象经注册表
// 解析到 System32 的原版，永远不会走我们这份副本，导出它们只会与 combaseapi.h
// 的既有声明（REFCLSID/REFIID 引用形参）撞签名。
static FARPROC p_DwmAttachMilContent = nullptr;
static FARPROC p_DwmDefWindowProc = nullptr;
static FARPROC p_DwmDetachMilContent = nullptr;
static FARPROC p_DwmEnableBlurBehindWindow = nullptr;
static FARPROC p_DwmEnableComposition = nullptr;
static FARPROC p_DwmEnableMMCSS = nullptr;
static FARPROC p_DwmExtendFrameIntoClientArea = nullptr;
static FARPROC p_DwmFlush = nullptr;
static FARPROC p_DwmGetColorizationColor = nullptr;
static FARPROC p_DwmGetCompositionTimingInfo = nullptr;
static FARPROC p_DwmGetGraphicsStreamClient = nullptr;
static FARPROC p_DwmGetGraphicsStreamTransformHint = nullptr;
static FARPROC p_DwmGetTransportAttributes = nullptr;
static FARPROC p_DwmGetUnmetTabRequirements = nullptr;
static FARPROC p_DwmGetWindowAttribute = nullptr;
static FARPROC p_DwmInvalidateIconicBitmaps = nullptr;
static FARPROC p_DwmIsCompositionEnabled = nullptr;
static FARPROC p_DwmModifyPreviousDxFrameDuration = nullptr;
static FARPROC p_DwmQueryThumbnailSourceSize = nullptr;
static FARPROC p_DwmRegisterThumbnail = nullptr;
static FARPROC p_DwmRenderGesture = nullptr;
static FARPROC p_DwmSetDxFrameDuration = nullptr;
static FARPROC p_DwmSetIconicLivePreviewBitmap = nullptr;
static FARPROC p_DwmSetIconicThumbnail = nullptr;
static FARPROC p_DwmSetPresentParameters = nullptr;
static FARPROC p_DwmSetWindowAttribute = nullptr;
static FARPROC p_DwmShowContact = nullptr;
static FARPROC p_DwmTetherContact = nullptr;
static FARPROC p_DwmTransitionOwnedWindow = nullptr;
static FARPROC p_DwmUnregisterThumbnail = nullptr;
static FARPROC p_DwmUpdateThumbnailProperties = nullptr;

static void EnsureRealDwmapi()
{
    // magic static：只初始化一次且线程安全，多线程首次并发调用也只加载一次真身。
    static const bool ready = [] {
        char realPath[MAX_PATH + 16] = {};
        if (!GetSystemDirectoryA(realPath, MAX_PATH))
            return false;
        lstrcatA(realPath, "\\dwmapi.dll");
        g_hRealDwmapi = LoadLibraryA(realPath);
        if (!g_hRealDwmapi)
            return false;
        const struct { const char* Name; FARPROC* Slot; } entries[] = {
            { "DwmAttachMilContent", &p_DwmAttachMilContent },
            { "DwmDefWindowProc", &p_DwmDefWindowProc },
            { "DwmDetachMilContent", &p_DwmDetachMilContent },
            { "DwmEnableBlurBehindWindow", &p_DwmEnableBlurBehindWindow },
            { "DwmEnableComposition", &p_DwmEnableComposition },
            { "DwmEnableMMCSS", &p_DwmEnableMMCSS },
            { "DwmExtendFrameIntoClientArea", &p_DwmExtendFrameIntoClientArea },
            { "DwmFlush", &p_DwmFlush },
            { "DwmGetColorizationColor", &p_DwmGetColorizationColor },
            { "DwmGetCompositionTimingInfo", &p_DwmGetCompositionTimingInfo },
            { "DwmGetGraphicsStreamClient", &p_DwmGetGraphicsStreamClient },
            { "DwmGetGraphicsStreamTransformHint", &p_DwmGetGraphicsStreamTransformHint },
            { "DwmGetTransportAttributes", &p_DwmGetTransportAttributes },
            { "DwmGetUnmetTabRequirements", &p_DwmGetUnmetTabRequirements },
            { "DwmGetWindowAttribute", &p_DwmGetWindowAttribute },
            { "DwmInvalidateIconicBitmaps", &p_DwmInvalidateIconicBitmaps },
            { "DwmIsCompositionEnabled", &p_DwmIsCompositionEnabled },
            { "DwmModifyPreviousDxFrameDuration", &p_DwmModifyPreviousDxFrameDuration },
            { "DwmQueryThumbnailSourceSize", &p_DwmQueryThumbnailSourceSize },
            { "DwmRegisterThumbnail", &p_DwmRegisterThumbnail },
            { "DwmRenderGesture", &p_DwmRenderGesture },
            { "DwmSetDxFrameDuration", &p_DwmSetDxFrameDuration },
            { "DwmSetIconicLivePreviewBitmap", &p_DwmSetIconicLivePreviewBitmap },
            { "DwmSetIconicThumbnail", &p_DwmSetIconicThumbnail },
            { "DwmSetPresentParameters", &p_DwmSetPresentParameters },
            { "DwmSetWindowAttribute", &p_DwmSetWindowAttribute },
            { "DwmShowContact", &p_DwmShowContact },
            { "DwmTetherContact", &p_DwmTetherContact },
            { "DwmTransitionOwnedWindow", &p_DwmTransitionOwnedWindow },
            { "DwmUnregisterThumbnail", &p_DwmUnregisterThumbnail },
            { "DwmUpdateThumbnailProperties", &p_DwmUpdateThumbnailProperties },
        };
        for (const auto& e : entries)
            *e.Slot = GetProcAddress(g_hRealDwmapi, e.Name);
        return true;
    }();
    (void)ready;
}

// 转发宏：按系统 dwmapi 的原始签名声明导出，调用时强转到同签名函数指针。
// 结构体指针一律用 void*/const void*：x64 下参数只按指针宽度传递，ABI 完全一致，
// 也就不必把 Dwmapi 内部的结构体定义搬进来。导出名与序数见 dwmapi.def。
#define OST_FORWARD_DWM(Ret, Name, Params, Args, FailValue)               \
    extern "C" Ret WINAPI Name Params                                     \
    {                                                                     \
        EnsureRealDwmapi();                                               \
        if (!p_##Name) return FailValue;                                  \
        return reinterpret_cast<Ret(WINAPI*)Params>(p_##Name) Args;       \
    }

OST_FORWARD_DWM(HRESULT, DwmAttachMilContent, (HWND hwnd), (hwnd), E_FAIL)
OST_FORWARD_DWM(BOOL, DwmDefWindowProc,
                (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, LRESULT* plResult),
                (hwnd, msg, wParam, lParam, plResult), FALSE)
OST_FORWARD_DWM(HRESULT, DwmDetachMilContent, (HWND hwnd), (hwnd), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmEnableBlurBehindWindow, (HWND hwnd, const void* pBlurBehind),
                (hwnd, pBlurBehind), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmEnableComposition, (UINT uCompositionAction), (uCompositionAction), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmEnableMMCSS, (BOOL fEnableMMCSS), (fEnableMMCSS), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmExtendFrameIntoClientArea, (HWND hwnd, const void* pMarInset),
                (hwnd, pMarInset), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmFlush, (), (), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetColorizationColor, (DWORD* pcrColorization, BOOL* pfOpaqueBlend),
                (pcrColorization, pfOpaqueBlend), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetCompositionTimingInfo, (HWND hwnd, void* pTimingInfo),
                (hwnd, pTimingInfo), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetGraphicsStreamClient, (UINT uIndex, void* pClientUuid),
                (uIndex, pClientUuid), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetGraphicsStreamTransformHint, (UINT uIndex, void* pTransform),
                (uIndex, pTransform), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetTransportAttributes,
                (BOOL* pfIsRemoting, BOOL* pfIsConnected, DWORD* pDwGeneration),
                (pfIsRemoting, pfIsConnected, pDwGeneration), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetUnmetTabRequirements, (HWND appWindow, void* value),
                (appWindow, value), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmGetWindowAttribute,
                (HWND hwnd, DWORD dwAttribute, void* pvAttribute, DWORD cbAttribute),
                (hwnd, dwAttribute, pvAttribute, cbAttribute), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmInvalidateIconicBitmaps, (HWND hwnd), (hwnd), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmIsCompositionEnabled, (BOOL* pfEnabled), (pfEnabled), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmModifyPreviousDxFrameDuration,
                (HWND hwnd, INT cRefreshes, BOOL fRelative), (hwnd, cRefreshes, fRelative), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmQueryThumbnailSourceSize, (HANDLE hThumbnail, void* pSize),
                (hThumbnail, pSize), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmRegisterThumbnail,
                (HWND hwndDestination, HWND hwndSource, HANDLE* phThumbnailId),
                (hwndDestination, hwndSource, phThumbnailId), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmRenderGesture,
                (int gt, UINT cContacts, const DWORD* pdwPointerID, const POINT* pPoints),
                (gt, cContacts, pdwPointerID, pPoints), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmSetDxFrameDuration, (HWND hwnd, INT cRefreshes),
                (hwnd, cRefreshes), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmSetIconicLivePreviewBitmap,
                (HWND hwnd, HBITMAP hbmp, void* pptClient, DWORD dwSITFlags),
                (hwnd, hbmp, pptClient, dwSITFlags), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmSetIconicThumbnail, (HWND hwnd, HBITMAP hbmp, DWORD dwSITFlags),
                (hwnd, hbmp, dwSITFlags), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmSetPresentParameters, (HWND hwnd, void* pPresentParams),
                (hwnd, pPresentParams), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmSetWindowAttribute,
                (HWND hwnd, DWORD dwAttribute, const void* pvAttribute, DWORD cbAttribute),
                (hwnd, dwAttribute, pvAttribute, cbAttribute), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmShowContact, (DWORD dwPointerID, DWORD eShowContact),
                (dwPointerID, eShowContact), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmTetherContact, (DWORD dwPointerID, BOOL fEnable, POINT ptTether),
                (dwPointerID, fEnable, ptTether), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmTransitionOwnedWindow, (HWND hwnd, int target), (hwnd, target), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmUnregisterThumbnail, (HANDLE hThumbnailId), (hThumbnailId), E_FAIL)
OST_FORWARD_DWM(HRESULT, DwmUpdateThumbnailProperties, (HANDLE hThumbnailId, const void* ptnProperties),
                (hThumbnailId, ptnProperties), E_FAIL)

#undef OST_FORWARD_DWM

// ─── OpenSteamTool injection ──────────────────────────────────────
// 只在宿主是 steam.exe 时注入（不区分大小写）；其它进程放行不注入。
static void OpenSteamToolLoad(HMODULE selfModule)
{
    char exePath[MAX_PATH] = {};
    const DWORD exeLen = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    // 拿不到宿主名或路径被截断（文件名不可信）就放弃注入：宁可漏注也不错杀。
    if (exeLen == 0 || exeLen >= MAX_PATH)
        return;
    const char* exeName = strrchr(exePath, '\\');
    exeName = exeName ? exeName + 1 : exePath;
    if (_stricmp(exeName, "steam.exe") != 0)
        return;

    // 按自身所在目录定位本体：不依赖 DLL 搜索顺序，也隔绝同目录之外的
    // 同名文件劫持（CWD/PATH 里塞假体）。代理放哪，本体就在哪。
    char selfPath[MAX_PATH + 16] = {};
    const DWORD selfLen = GetModuleFileNameA(selfModule, selfPath, MAX_PATH);
    if (selfLen == 0 || selfLen >= MAX_PATH)
        return;
    char* slash = strrchr(selfPath, '\\');
    if (!slash)
        return;
    lstrcpyA(slash + 1, "OpenSteamTool.dll");
    LoadLibraryA(selfPath);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        // 本模块是 Steam 加载链的一环：这里返回 FALSE 会连累调用方模块加载失败。
        // OpenSteamTool 载不进来（被杀软拦截、副本损坏）也只是放弃注入，放行 Steam。
        OpenSteamToolLoad(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
