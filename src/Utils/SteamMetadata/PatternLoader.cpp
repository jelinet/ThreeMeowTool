#include "PatternLoader.h"
#include "OSTPlatform/include/Memory.h"
#include "OSTPlatform/include/Numbers.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/RemoteToml.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"
#include "Utils/Support/FnvHash.h"

#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <toml++/toml.hpp>

// ---- compile-time sanity checks for FNV-1a table keys ----
// If the steam-monitor bot uses the same algorithm these must hold.
static_assert(Fnv1aHash("BBuildAndAsyncSendFrame") == 0x82428E37u,
              "FNV-1a mismatch for BBuildAndAsyncSendFrame");
static_assert(Fnv1aHash("BuildDepotDependency") == 0xC37F2D8Eu,
              "FNV-1a mismatch for BuildDepotDependency");

namespace {

// ---- per-function pattern record ----
struct PatternEntry {
    std::string name;
    uintptr_t   rva = 0;   // 0 = not present in file
    std::string sig;        // empty = not present in file
};

// key = Fnv1aHash(funcName)
using PatternMap = std::unordered_map<uint32_t, PatternEntry>;

// module → its pattern map
static std::unordered_map<OSTPlatform::DynamicLibrary::ModuleHandle, PatternMap> g_moduleMaps;

// Modules whose Load() call failed (popup already shown). FindPattern
// silently returns nullptr for these — without re-logging or adding the
// function to g_missingFunctions — so we don't follow one "TOML missing"
// popup with a second popup listing every dependent hook.
static std::unordered_set<OSTPlatform::DynamicLibrary::ModuleHandle> g_failedModules;

// functions whose names were not found during FindPattern
static std::vector<std::string> g_missingFunctions;

// 各模块 Load() 时的请求（给缺条目自愈用：见 FindPattern）。
static std::unordered_map<OSTPlatform::DynamicLibrary::ModuleHandle, RemoteToml::Request> g_moduleReqs;

// 本会话已刷新过的模块（只一次；刷完还缺就是上游真没有，走正常缺失上报）。
static std::unordered_set<OSTPlatform::DynamicLibrary::ModuleHandle> g_refreshedModules;

// ---- byte-pattern scanner ----

static bool ParseSig(const std::string& str,
                     std::vector<uint8_t>& bytes,
                     std::vector<uint8_t>& mask)
{
    bytes.clear();
    mask.clear();
    for (const char* p = str.c_str(); *p; ) {
        if (*p == ' ' || *p == '\t' || *p == ',') { ++p; continue; }
        if (p[0] == '?' && p[1] == '?') {
            bytes.push_back(0); mask.push_back(0); p += 2; continue;
        }
        char hi = p[0], lo = p[1];
        if (!hi || !lo) return false;
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = nib(hi), l = nib(lo);
        if (h < 0 || l < 0) return false;
        bytes.push_back(static_cast<uint8_t>((h << 4) | l));
        mask.push_back(1);
        p += 2;
    }
    return !bytes.empty();
}

static void* ScanModule(OSTPlatform::DynamicLibrary::ModuleHandle module,
                        const std::vector<uint8_t>& bytes,
                        const std::vector<uint8_t>& mask)
{
    const auto image = OSTPlatform::Memory::GetModuleImage(module);
    if (!image) return nullptr;

    auto* base = image->base;
    size_t size = image->size;
    size_t patLen = bytes.size();
    if (size < patLen) return nullptr;

    for (size_t i = 0; i <= size - patLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patLen; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) { found = false; break; }
        }
        if (found) return base + i;
    }
    return nullptr;
}

// ---- TOML pattern parser ----

// Section keys are hex literals like "0x82428E37"; each section is a table
// with optional `name`, `rva` (hex string), and `sig` (IDA-style bytes).
static PatternMap TableToPatternMap(const toml::table& tbl)
{
    PatternMap map;
    map.reserve(tbl.size());
    for (auto& [rawKey, val] : tbl) {
        if (!val.is_table()) continue;
        auto& sub = *val.as_table();

        const auto parsedKey = OSTPlatform::Numbers::ParseHexUInt32(std::string(rawKey));
        if (!parsedKey) continue;
        const uint32_t hashKey = *parsedKey;

        PatternEntry entry;
        if (auto v = sub["name"].value<std::string>()) entry.name = *v;
        if (auto v = sub["rva"].value<std::string>()) {
            if (const auto rva = OSTPlatform::Numbers::ParseHexUInt64(*v)) {
                entry.rva = static_cast<uintptr_t>(*rva);
            }
        }
        if (auto v = sub["sig"].value<std::string>()) entry.sig = *v;

        map[hashKey] = std::move(entry);
    }
    return map;
}

static PatternMap ParsePatternString(std::string_view body,
                                     std::string* outError = nullptr)
{
    try {
        return TableToPatternMap(toml::parse(body));
    } catch (const toml::parse_error& e) {
        if (outError) *outError = e.description();
        return {};
    }
}

// ---- popup helpers (detached threads so we never block Steam) ----

// Surface a missing pattern file to the user, with enough detail to either
// (a) drop a file in manually, (b) check the upstream repo, or (c) file
// an actionable bug report.  We deliberately only disable hooks for the
// failing module — the rest of OpenSteamTool keeps working.
static void ShowDownloadFailedPopup(const std::string& dllName,
                                    const std::string& sha256,
                                    const std::string& component)
{
    SteamDiagnostics::ShowWarning(
            "OpenSteamTool - 不支持的 Steam 版本",
            "OpenSteamTool：找不到 " + dllName + " 的签名文件。\n\n"
            "依赖 " + dllName + " 的 hook 将在本会话中停用，"
            "其他模块不受影响。\n\n"
            "你可以：\n"
            "方法1：前往下方 Github 链接下载 Fluent Steam Lua 入库管理工具\n"
            "https://github.com/huanyuejue/Fluent-Steam-Lua\n"
            "在软件右下角工具面板的 OpenSteamTool 管理面板中一键补齐所需 Toml 文件\n"
            "\n\n"
            "方法2：手动去 Github 上游获取一份匹配的 TOML 放到本地的：\n"
            "<Steam>\\opensteamtool\\pattern\\" + component + "\\" + sha256 + ".toml\n"
            "\n\n"
            "上游地址：\n"
            "https://github.com/huanyuejue/steam-monitor/tree/main/pattern/" + component + "\n"
            "\n\n"
            "如仍无法解决，可按下方诊断信息反馈至：\n"
            "https://github.com/huanyuejue/OpenSteamTool/issues");
}

} // namespace

// ---- public API ----

namespace PatternLoader {

    constexpr const char* kPatternChannel = "pattern";

bool Load(OSTPlatform::DynamicLibrary::ModuleHandle module, const std::string& dllPath, const std::string& component)
{
    namespace fs = std::filesystem;
    const RemoteToml::Request req{ kPatternChannel, component, dllPath };
    const std::string dllName = fs::path(dllPath).filename().string();

    auto tryParse = [&](const RemoteToml::Result& res, PatternMap& out, std::string& err) -> bool {
        if (!res.ok) return false;
        out = ParsePatternString(res.body, &err);
        return !out.empty();
    };

    // Delegate fetch + cache + mirror fallback to RemoteToml.
    PatternMap map;
    std::string parseErr;
    RemoteToml::Result r = RemoteToml::Fetch(req);
    if (tryParse(r, map, parseErr)) {
        LOG_INFO("PatternLoader: loaded {} patterns for {} ({})",
                 map.size(), component, r.fromCache ? "cache" : "remote");
        g_moduleMaps[module] = std::move(map);
        g_moduleReqs[module] = req;
        return true;
    }

    // 自愈：只有"缓存有内容但解析空"才值得删了重下（串台文件）；
    // 下载失败/远端坏内容重下也没用。只一次。
    if (r.ok && r.fromCache) {
        LOG_WARN("PatternLoader: parsed empty spec for {} ({}), dropping stale cache and refetching once",
                 component, parseErr.empty() ? "no entries" : parseErr);
        RemoteToml::Invalidate(req);
        r = RemoteToml::Fetch(req);
        parseErr.clear();
        if (tryParse(r, map, parseErr)) {
            LOG_INFO("PatternLoader: self-heal ok, loaded {} patterns for {} ({})",
                     map.size(), component, r.fromCache ? "cache" : "remote");
            g_moduleMaps[module] = std::move(map);
            g_moduleReqs[module] = req;
            return true;
        }
    } else if (!r.ok) {
        LOG_WARN("PatternLoader: download failed for {} (see RemoteToml log above)", component);
    } else {
        LOG_WARN("PatternLoader: TOML for {} parsed empty ({})",
                 component, parseErr.empty() ? "no entries" : parseErr);
    }

    // 失败即弹窗：缺文件就告诉用户，不静默。
    std::string sha = r.sha256.empty() ? "(hash failed)" : r.sha256;
    ShowDownloadFailedPopup(dllName, sha, component);
    g_failedModules.insert(module);
    return false;
}

void* FindPattern(OSTPlatform::DynamicLibrary::ModuleHandle module, const char* funcName)
{
    // If the whole module's pattern file failed to load, stay quiet — the
    // user already saw one popup and the main.log already has the warning.
    // No point amplifying that into one log line per hook plus a second
    // "missing functions" popup later.
    if (g_failedModules.count(module)) {
        return nullptr;
    }

    uint32_t key = Fnv1aHash(funcName);

    auto mapIt = g_moduleMaps.find(module);
    if (mapIt == g_moduleMaps.end()) {
        // Load() was never called for this module.
        LOG_WARN("PatternLoader: FindPattern called for module that was never loaded "
                 "('{}')", funcName);
        g_missingFunctions.emplace_back(funcName);
        return nullptr;
    }

    auto& map = mapIt->second;
    auto entryIt = map.find(key);
    if (entryIt == map.end()) {
        // 子集缓存自愈：同一 sha 的签名文件会被上游补全，缓存按 sha 当不可变存着，
        // 不刷就会一直缺同一批函数。每个模块每会话只刷一次：刷完还缺就是上游真没有，
        // 走正常缺失上报。
        // 注意这里跑在 Install 阶段里（调用方就是装 hook 的），刷完直接继续查，
        // 补回来的条目同一次就能装上，不用等下次启动。
        // 这次重抓发生在装 hook 的事务窗口里，慢，但每模块每会话只走一次。
        if (!g_refreshedModules.count(module)) {
            g_refreshedModules.insert(module);
            const auto reqIt = g_moduleReqs.find(module);
            if (reqIt != g_moduleReqs.end()) {
                LOG_WARN("PatternLoader: '{}' not in cached spec, dropping possibly-stale subset and refetching once",
                         funcName);
                RemoteToml::Invalidate(reqIt->second);
                RemoteToml::Result r = RemoteToml::Fetch(reqIt->second);
                if (r.ok) {
                    std::string refreshErr;
                    PatternMap fresh = ParsePatternString(r.body, &refreshErr);
                    // 非空才算数：空/坏继续用旧 map（总比没有强）。
                    if (!fresh.empty()) {
                        LOG_INFO("PatternLoader: subset refresh ok, {} -> {} entries ({})",
                                 map.size(), fresh.size(), r.fromCache ? "cache" : "remote");
                        map = std::move(fresh);
                        entryIt = map.find(key);
                    } else {
                        LOG_WARN("PatternLoader: subset refresh parsed empty ({}), keeping old map",
                                 refreshErr.empty() ? "no entries" : refreshErr);
                    }
                }
            }
        }
    }
    if (entryIt == map.end()) {
        LOG_WARN("PatternLoader: no entry for '{}' (key=0x{:08X})", funcName, key);
        g_missingFunctions.emplace_back(funcName);
        return nullptr;
    }

    const PatternEntry& entry = entryIt->second;

    // Priority 1: RVA direct offset
    if (entry.rva != 0) {
        void* addr = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(module) + entry.rva);
        LOG_DEBUG("PatternLoader: {} resolved via RVA 0x{:X}", funcName, entry.rva);
        return addr;
    }

    // Priority 2: byte-signature scan
    if (!entry.sig.empty()) {
        std::vector<uint8_t> bytes, mask;
        if (ParseSig(entry.sig, bytes, mask)) {
            void* addr = ScanModule(module, bytes, mask);
            if (addr) {
                uintptr_t rva = reinterpret_cast<uintptr_t>(addr) -
                                reinterpret_cast<uintptr_t>(module);
                LOG_DEBUG("PatternLoader: {} resolved via sig @ RVA 0x{:X}",
                          funcName, rva);
                return addr;
            }
            LOG_WARN("PatternLoader: sig scan miss for '{}' (pattern parsed OK, "
                     "no match in module image)", funcName);
        } else {
            LOG_WARN("PatternLoader: malformed sig for '{}': '{}'",
                     funcName, entry.sig);
        }
    } else {
        LOG_WARN("PatternLoader: entry for '{}' has neither rva nor sig", funcName);
    }

    g_missingFunctions.emplace_back(funcName);
    return nullptr;
}

void ReportMissingFunctions()
{
    if (g_missingFunctions.empty()) return;

    // Build the list
    std::string list;
    for (const auto& name : g_missingFunctions)
        list += "  - " + name + "\n";
    g_missingFunctions.clear();

    SteamDiagnostics::ShowWarning(
        "OpenSteamTool - 签名缺失",
        "OpenSteamTool：部分函数未能定位。\n\n"
        "以下函数在签名文件中找不到：\n" +
        list +
        "\n这些函数的 hook 将在本会话中停用。\n\n"
        "请按此反馈：\n"
        "https://github.com/huanyuejue/OpenSteamTool/issues");
}

} // namespace PatternLoader
