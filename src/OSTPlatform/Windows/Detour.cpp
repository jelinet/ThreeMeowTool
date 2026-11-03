#include "include/Detour.h"

#include "include/Log.h"
#include "include/Thread.h"

#include <windows.h>
#include <detours.h>
#include <tlhelp32.h>

#include <vector>

namespace OSTPlatform::Detour {

namespace {

bool DetourSucceeded(LONG result, const char* operation) {
    if (result == NO_ERROR) return true;
    OSTP_LOG_WARN("{} failed (detours_error={})", operation, result);
    return false;
}

std::vector<HANDLE> s_updatedThreads;  // 登记过的线程句柄，commit 前必须一直有效

// 装卸事务必须登记进程全部线程：commit 改目标函数头几个字节时，
// 正好压在 trampoline 里跑的线程只有登记了才会被 Detours 挂起并修正上下文；
// 只登记当前线程的话，流量正跑时的二次装卸会改别的线程脚下的代码。
void UpdateAllThreads() {
    const DWORD self = GetCurrentThreadId();
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != GetCurrentProcessId()) continue;
            if (te.th32ThreadID == self) continue;  // 当前线程后面单独登记
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                  THREAD_QUERY_INFORMATION,
                                  FALSE, te.th32ThreadID);
            if (!h) continue;  // 线程刚好退出了，跳过
            DWORD exitCode = STILL_ACTIVE;
            if (!GetExitCodeThread(h, &exitCode) || exitCode != STILL_ACTIVE) {
                // 快照到打开之间退掉的僵尸 TID 不登记。
                CloseHandle(h);
                continue;
            }
            if (GetProcessIdOfThread(h) != GetCurrentProcessId()) {
                // TID 被别的进程复用也不登记：跨进程句柄会让 Detours 报错，
                // 并毒化整个事务（后面 Attach/Commit 全连带失败，hook 装不上）。
                CloseHandle(h);
                continue;
            }
            // 单个登记失败只跳过它，绝不往外抛——抛一次毒化整个事务。
            if (DetourUpdateThread(h) == NO_ERROR) {
                s_updatedThreads.push_back(h);
            } else {
                CloseHandle(h);
            }
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);
}

void CloseUpdatedThreads() {
    for (const HANDLE h : s_updatedThreads) CloseHandle(h);
    s_updatedThreads.clear();
}

} // namespace

bool BeginTransaction() {
    const LONG begin = DetourTransactionBegin();
    if (!DetourSucceeded(begin, "DetourTransactionBegin")) return false;
    UpdateAllThreads();
    return DetourSucceeded(
        DetourUpdateThread(Thread::CurrentNativeThreadHandle()),
        "DetourUpdateThread");
}

bool CommitTransaction() {
    const bool ok = DetourSucceeded(DetourTransactionCommit(), "DetourTransactionCommit");
    // 不管 commit 成败，登记时开的句柄都要关掉，不然每次装卸都漏一小把。
    CloseUpdatedThreads();
    return ok;
}

bool Attach(void** target, void* detour) {
    return DetourSucceeded(
        DetourAttach(reinterpret_cast<PVOID*>(target), reinterpret_cast<PVOID>(detour)),
        "DetourAttach");
}

bool Detach(void** target, void* detour) {
    return DetourSucceeded(
        DetourDetach(reinterpret_cast<PVOID*>(target), reinterpret_cast<PVOID>(detour)),
        "DetourDetach");
}

} // namespace OSTPlatform::Detour
