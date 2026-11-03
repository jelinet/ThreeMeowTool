// version.dll HiJack Project - loader-stage agent.
//
// steam.exe 的静态导入表里有 VERSION.dll，把这个代理放进 Steam 目录后，
// 它随加载器在进程初始化阶段就进入进程——比 Steam 首次加载 steamclient64.dll
// 更早。OpenSteamTool 因此能抢在首载之前架好重定向视野（首载抢劫 + 句柄改道）。
// 本模块运行在 steam.exe 的启动关键路径上：导出必须全量转发、DllMain 绝不能
// 失败，否则静态导入解析失败会直接让 Steam 起不来。

#include <windows.h>

// ─── 1. Real system version.dll binding ──────────────────────────
// 必须用 System32 全路径绑定真身：按名 LoadLibrary("version.dll") 会命中本模块。
static HMODULE g_hRealVersion = nullptr;

static FARPROC g_pGetFileVersionInfoA = nullptr;
static FARPROC g_pGetFileVersionInfoByHandle = nullptr;
static FARPROC g_pGetFileVersionInfoExA = nullptr;
static FARPROC g_pGetFileVersionInfoExW = nullptr;
static FARPROC g_pGetFileVersionInfoSizeA = nullptr;
static FARPROC g_pGetFileVersionInfoSizeExA = nullptr;
static FARPROC g_pGetFileVersionInfoSizeExW = nullptr;
static FARPROC g_pGetFileVersionInfoSizeW = nullptr;
static FARPROC g_pGetFileVersionInfoW = nullptr;
static FARPROC g_pVerFindFileA = nullptr;
static FARPROC g_pVerFindFileW = nullptr;
static FARPROC g_pVerInstallFileA = nullptr;
static FARPROC g_pVerInstallFileW = nullptr;
static FARPROC g_pVerLanguageNameA = nullptr;
static FARPROC g_pVerLanguageNameW = nullptr;
static FARPROC g_pVerQueryValueA = nullptr;
static FARPROC g_pVerQueryValueW = nullptr;

static void EnsureRealVersion()
{
    // magic static：只初始化一次且线程安全，多线程首次并发调用也只加载一次真身。
    static const bool ready = [] {
        char realPath[MAX_PATH + 16] = {};
        if (!GetSystemDirectoryA(realPath, MAX_PATH))
            return false;
        lstrcatA(realPath, "\\version.dll");
        g_hRealVersion = LoadLibraryA(realPath);
        if (!g_hRealVersion)
            return false;
        const struct { const char* Name; FARPROC* Slot; } entries[] = {
            { "GetFileVersionInfoA", &g_pGetFileVersionInfoA },
            { "GetFileVersionInfoByHandle", &g_pGetFileVersionInfoByHandle },
            { "GetFileVersionInfoExA", &g_pGetFileVersionInfoExA },
            { "GetFileVersionInfoExW", &g_pGetFileVersionInfoExW },
            { "GetFileVersionInfoSizeA", &g_pGetFileVersionInfoSizeA },
            { "GetFileVersionInfoSizeExA", &g_pGetFileVersionInfoSizeExA },
            { "GetFileVersionInfoSizeExW", &g_pGetFileVersionInfoSizeExW },
            { "GetFileVersionInfoSizeW", &g_pGetFileVersionInfoSizeW },
            { "GetFileVersionInfoW", &g_pGetFileVersionInfoW },
            { "VerFindFileA", &g_pVerFindFileA },
            { "VerFindFileW", &g_pVerFindFileW },
            { "VerInstallFileA", &g_pVerInstallFileA },
            { "VerInstallFileW", &g_pVerInstallFileW },
            { "VerLanguageNameA", &g_pVerLanguageNameA },
            { "VerLanguageNameW", &g_pVerLanguageNameW },
            { "VerQueryValueA", &g_pVerQueryValueA },
            { "VerQueryValueW", &g_pVerQueryValueW },
        };
        for (const auto& e : entries)
            *e.Slot = GetProcAddress(g_hRealVersion, e.Name);
        return true;
    }();
    (void)ready;
}

// ─── 2. Forwarded exports（序数与系统 version.dll 对齐，名字相同）─────
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA,@1")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA,@3")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW,@4")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW,@9")
#pragma comment(linker, "/EXPORT:VerFindFileA,@10")
#pragma comment(linker, "/EXPORT:VerFindFileW,@11")
#pragma comment(linker, "/EXPORT:VerInstallFileA,@12")
#pragma comment(linker, "/EXPORT:VerInstallFileW,@13")
#pragma comment(linker, "/EXPORT:VerLanguageNameA,@14")
#pragma comment(linker, "/EXPORT:VerLanguageNameW,@15")
#pragma comment(linker, "/EXPORT:VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW,@17")

extern "C" BOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoA) return FALSE;
    return reinterpret_cast<decltype(&GetFileVersionInfoA)>(g_pGetFileVersionInfoA)(lptstrFilename, dwHandle, dwLen, lpData);
}

extern "C" BOOL WINAPI GetFileVersionInfoByHandle(DWORD dwFlags, HANDLE hFile, LPVOID* lplpData, PDWORD pdwLen)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoByHandle) return FALSE;
    return reinterpret_cast<decltype(&GetFileVersionInfoByHandle)>(g_pGetFileVersionInfoByHandle)(dwFlags, hFile, lplpData, pdwLen);
}

extern "C" BOOL WINAPI GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoExA) return FALSE;
    return reinterpret_cast<decltype(&GetFileVersionInfoExA)>(g_pGetFileVersionInfoExA)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

extern "C" BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoExW) return FALSE;
    return reinterpret_cast<decltype(&GetFileVersionInfoExW)>(g_pGetFileVersionInfoExW)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

extern "C" DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoSizeA) return 0;
    return reinterpret_cast<decltype(&GetFileVersionInfoSizeA)>(g_pGetFileVersionInfoSizeA)(lptstrFilename, lpdwHandle);
}

extern "C" DWORD WINAPI GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoSizeExA) return 0;
    return reinterpret_cast<decltype(&GetFileVersionInfoSizeExA)>(g_pGetFileVersionInfoSizeExA)(dwFlags, lpwstrFilename, lpdwHandle);
}

extern "C" DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoSizeExW) return 0;
    return reinterpret_cast<decltype(&GetFileVersionInfoSizeExW)>(g_pGetFileVersionInfoSizeExW)(dwFlags, lpwstrFilename, lpdwHandle);
}

extern "C" DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoSizeW) return 0;
    return reinterpret_cast<decltype(&GetFileVersionInfoSizeW)>(g_pGetFileVersionInfoSizeW)(lptstrFilename, lpdwHandle);
}

extern "C" BOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    EnsureRealVersion();
    if (!g_pGetFileVersionInfoW) return FALSE;
    return reinterpret_cast<decltype(&GetFileVersionInfoW)>(g_pGetFileVersionInfoW)(lptstrFilename, dwHandle, dwLen, lpData);
}

extern "C" DWORD WINAPI VerFindFileA(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir,
                                     LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen)
{
    EnsureRealVersion();
    if (!g_pVerFindFileA) return 0;
    return reinterpret_cast<decltype(&VerFindFileA)>(g_pVerFindFileA)(uFlags, szFileName, szWinDir, szAppDir,
                                                                     szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

extern "C" DWORD WINAPI VerFindFileW(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir,
                                     LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen)
{
    EnsureRealVersion();
    if (!g_pVerFindFileW) return 0;
    return reinterpret_cast<decltype(&VerFindFileW)>(g_pVerFindFileW)(uFlags, szFileName, szWinDir, szAppDir,
                                                                     szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

extern "C" DWORD WINAPI VerInstallFileA(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName,
                                        LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir,
                                        LPSTR szTmpFile, PUINT puTmpFileLen)
{
    EnsureRealVersion();
    if (!g_pVerInstallFileA) return 0;
    return reinterpret_cast<decltype(&VerInstallFileA)>(g_pVerInstallFileA)(uFlags, szSrcFileName, szDestFileName,
                                                                            szSrcDir, szDestDir, szCurDir,
                                                                            szTmpFile, puTmpFileLen);
}

extern "C" DWORD WINAPI VerInstallFileW(DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName,
                                        LPCWSTR szSrcDir, LPCWSTR szDestDir, LPCWSTR szCurDir,
                                        LPWSTR szTmpFile, PUINT puTmpFileLen)
{
    EnsureRealVersion();
    if (!g_pVerInstallFileW) return 0;
    return reinterpret_cast<decltype(&VerInstallFileW)>(g_pVerInstallFileW)(uFlags, szSrcFileName, szDestFileName,
                                                                            szSrcDir, szDestDir, szCurDir,
                                                                            szTmpFile, puTmpFileLen);
}

extern "C" DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang)
{
    EnsureRealVersion();
    if (!g_pVerLanguageNameA) return 0;
    return reinterpret_cast<decltype(&VerLanguageNameA)>(g_pVerLanguageNameA)(wLang, szLang, cchLang);
}

extern "C" DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang)
{
    EnsureRealVersion();
    if (!g_pVerLanguageNameW) return 0;
    return reinterpret_cast<decltype(&VerLanguageNameW)>(g_pVerLanguageNameW)(wLang, szLang, cchLang);
}

extern "C" BOOL WINAPI VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)
{
    EnsureRealVersion();
    if (!g_pVerQueryValueA) return FALSE;
    return reinterpret_cast<decltype(&VerQueryValueA)>(g_pVerQueryValueA)(pBlock, lpSubBlock, lplpBuffer, puLen);
}

extern "C" BOOL WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)
{
    EnsureRealVersion();
    if (!g_pVerQueryValueW) return FALSE;
    return reinterpret_cast<decltype(&VerQueryValueW)>(g_pVerQueryValueW)(pBlock, lpSubBlock, lplpBuffer, puLen);
}

// ─── 3. OpenSteamTool injection ───────────────────────────────────
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
        // 本模块是 steam.exe 的静态导入：这里返回 FALSE 会让进程初始化直接失败。
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
