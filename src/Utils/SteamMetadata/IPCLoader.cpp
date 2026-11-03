#include "IPCLoader.h"
#include "IPCMessages.gen.h"
#include "OSTPlatform/include/Numbers.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/RemoteToml.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"

#include <unordered_map>
#include <utility>

#include <toml++/toml.hpp>

namespace IPCLoader {

namespace {

    struct Registry {
        std::vector<Interface> interfaces;
        std::unordered_map<EIPCInterface, size_t> byID;
        std::unordered_map<std::string, size_t> byName;

        void Clear()
        {
            interfaces.clear();
            byID.clear();
            byName.clear();
        }

        void Add(Interface iface)
        {
            const size_t index = interfaces.size();
            byID[iface.id] = index;
            byName[iface.name] = index;
            interfaces.push_back(std::move(iface));
        }

        const Method* Find(EIPCInterface interfaceID, uint32_t funcHash) const
        {
            const auto it = byID.find(interfaceID);
            if (it == byID.end()) return nullptr;

            for (const auto& method : interfaces[it->second].methods) {
                if (method.funcHash == funcHash) return &method;
            }
            return nullptr;
        }

        const Method* Find(std::string_view interfaceName,
                           std::string_view methodName) const
        {
            const auto it = byName.find(std::string(interfaceName));
            if (it == byName.end()) return nullptr;

            for (const auto& method : interfaces[it->second].methods) {
                if (method.name == methodName) return &method;
            }
            return nullptr;
        }

        bool HasInterface(std::string_view interfaceName) const
        {
            const auto it = byName.find(std::string(interfaceName));
            return it != byName.end() && !interfaces[it->second].methods.empty();
        }

        size_t MethodCount() const
        {
            size_t count = 0;
            for (const auto& iface : interfaces)
                count += iface.methods.size();
            return count;
        }
    };

    Registry g_registry;

    // ---- TOML helpers ----

    static bool ParseHexU32(std::string_view s, uint32_t& out)
    {
        const auto parsed = OSTPlatform::Numbers::ParseHexUInt32(s);
        if (!parsed) return false;
        out = *parsed;
        return true;
    }

    static bool ParseInterfaceTable(std::string_view name,
                                    const toml::table& tbl,
                                    Interface& out)
    {
        out.name = std::string(name);

        const auto expected = EIPCInterfaceFromName(name);
        if (!expected) {
            LOG_WARN("IPCLoader: [{}] is not declared in EIPCInterface", name);
            return false;
        }
        out.id = *expected;

        // Backward-compatible metadata: EIPCInterface is authoritative.
        if (auto v = tbl["interface_id"].value<int64_t>()) {
            if (*v < 0 || *v > 0xFF) {
                LOG_WARN("IPCLoader: [{}] interface_id out of range ({})", name, *v);
                return false;
            }
            if (static_cast<EIPCInterface>(*v) != out.id) {
                LOG_WARN("IPCLoader: [{}] interface_id {} disagrees with generated EIPCInterface value {}",
                         name, *v, static_cast<uint8_t>(out.id));
                return false;
            }
        }

        if (auto v = tbl["vtable_rva"].value<std::string>())
            ParseHexU32(*v, out.vtableRva);

        // Walk dotted sub-tables — each is a method.
        for (auto& [methodKey, methodVal] : tbl) {
            if (!methodVal.is_table()) continue;
            const auto& mtbl = *methodVal.as_table();

            Method m;
            m.interfaceID = out.id;
            m.name = std::string(methodKey.str());

            if (auto v = mtbl["funcHash"].value<std::string>()) {
                if (!ParseHexU32(*v, m.funcHash)) {
                    LOG_WARN("IPCLoader: [{}.{}] bad funcHash '{}'",
                             name, m.name, *v);
                    continue;
                }
            } else {
                LOG_WARN("IPCLoader: [{}.{}] missing funcHash", name, m.name);
                continue;
            }

            if (auto v = mtbl["fencepost"].value<std::string>())
                ParseHexU32(*v, m.fencepost);
            if (auto v = mtbl["argc"].value<int64_t>())
                m.argc = static_cast<uint32_t>(*v);
            out.methods.push_back(std::move(m));
        }
        return true;
    }

    static void ShowMissingPopup(const std::string& sha256)
    {
        SteamDiagnostics::ShowWarning(
            "OpenSteamTool - 缺少 IPC 描述文件",
            "OpenSteamTool：找不到 IPC 描述文件。\n\n"
            "本会话 IPC 拦截已停用，基于特征码的 hook 不受影响。\n\n"
            "你可以：\n"
            "方法1：前往下方 Github 链接下载 Fluent Steam Lua 入库管理工具\n"
            "https://github.com/huanyuejue/Fluent-Steam-Lua\n"
            "在软件右下角工具面板的 OpenSteamTool 管理面板中一键补齐所需 Toml 文件\n"
            "\n\n"
            "方法2：手动去 Github 上游获取一份匹配的 TOML 放到本地的：\n"
            "<Steam>\\opensteamtool\\ipc\\steamclient\\" + sha256 + ".toml\n"
            "\n\n"
            "上游地址：\n"
            "https://github.com/huanyuejue/steam-monitor/tree/main/ipc/steamclient\n"
            "\n\n"
            "如仍无法解决，可按下方诊断信息反馈至：\n"
            "https://github.com/huanyuejue/OpenSteamTool/issues");
    }

} // namespace

constexpr const char* kIPCChannel = "ipc";

// 必需的接口表：我们的 handler 全在这两个下面。缺任何一个等于 IPC 票据层全灭，
// 必须当失败处理，不能当成功糊弄过去（实测：串台的 pattern 文件会导致 0 方法 + 静默 54）。
constexpr const char* kRequiredInterfaces[] = { "IClientUser", "IClientUtils" };

static bool HasRequiredInterfaces()
{
    for (const char* name : kRequiredInterfaces) {
        if (!g_registry.HasInterface(name)) return false;
    }
    return true;
}

// TryLoadOnce 结果分三类：Ok 直接用；Retryable（缓存有内容但坏）值得删缓存重下一次；
// Fatal（下载失败/远端内容坏）重下也没用，直接大声失败。绝不无脑重试，避免离线时
// 启动路径上付双倍网络超时。
enum class TryResult { Ok, Retryable, Fatal };

static TryResult TryLoadOnce(const std::string& steamclientPath, std::string& sha256, bool& fromCache, bool& allNotFound)
{
    RemoteToml::Result r = RemoteToml::Fetch({
        kIPCChannel,
        "steamclient",
        steamclientPath,
    });
    sha256 = r.sha256;
    fromCache = r.fromCache;
    allNotFound = r.allNotFound;

    if (!r.ok) return TryResult::Fatal;

    toml::table root;
    try {
        root = toml::parse(r.body);
    } catch (const toml::parse_error& e) {
        LOG_WARN("IPCLoader: TOML parse error: {}", e.description());
        // 缓存截断才值得重下；远端坏内容重下也一样。
        return fromCache ? TryResult::Retryable : TryResult::Fatal;
    }

    for (auto& [key, val] : root) {
        if (!val.is_table()) continue;
        Interface iface;
        if (!ParseInterfaceTable(key.str(), *val.as_table(), iface)) continue;

        g_registry.Add(std::move(iface));
    }

    if (!HasRequiredInterfaces()) {
        // 远端坏内容重下也没用；只有缓存串台才值得自愈。
        return fromCache ? TryResult::Retryable : TryResult::Fatal;
    }
    return TryResult::Ok;
}

bool Load(const std::string& steamclientPath)
{
    g_registry.Clear();

    std::string sha256;
    bool fromCache = false;
    bool allNotFound = false;
    const TryResult first = TryLoadOnce(steamclientPath, sha256, fromCache, allNotFound);
    if (first == TryResult::Ok) {
        LOG_INFO("IPCLoader: loaded {} methods across {} interfaces ({})",
                 MethodCount(), InterfaceCount(),
                 fromCache ? "cache" : "remote");
        return true;
    }

    // 自愈仅当缓存串台：删掉重下一次（上游当前给的就是对的格式，一次根治）。
    // 下载失败/远端内容坏重下也没用，直接大声失败，不浪费启动时间。
    // 只重试一次，避免下载循环。
    if (first == TryResult::Retryable) {
        LOG_WARN("IPCLoader: parsed spec missing required interfaces, dropping stale cache and refetching once");
        RemoteToml::Invalidate({ kIPCChannel, "steamclient", steamclientPath });
        g_registry.Clear();
        if (TryLoadOnce(steamclientPath, sha256, fromCache, allNotFound) == TryResult::Ok) {
            LOG_INFO("IPCLoader: self-heal ok, loaded {} methods across {} interfaces ({})",
                     MethodCount(), InterfaceCount(),
                     fromCache ? "cache" : "remote");
            return true;
        }
    }

    // 大声失败：缺文件就弹窗，不静默。
    // 0 方法还当成功是玄学 54 的根源，绝不再静默。
    if (allNotFound) {
        LOG_ERROR("IPCLoader: IPC spec not published upstream, IPC interception disabled for this session");
    } else {
        LOG_ERROR("IPCLoader: IPC spec download failed (network or bad upstream content), "
                  "IPC interception disabled for this session; will retry next launch");
    }
    ShowMissingPopup(sha256.empty() ? "(hash failed)" : sha256);
    return false;
}

const Method* Find(EIPCInterface interfaceID, uint32_t funcHash)
{
    return g_registry.Find(interfaceID, funcHash);
}

const Method* Find(std::string_view ifaceName, std::string_view methodName)
{
    return g_registry.Find(ifaceName, methodName);
}

size_t InterfaceCount() 
{ 
    return g_registry.interfaces.size();
}

size_t MethodCount() {
    return g_registry.MethodCount();
}

} // namespace IPCLoader
