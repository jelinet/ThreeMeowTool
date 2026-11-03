#include "RemoteToml.h"
#include "OSTPlatform/include/Http.h"
#include "Utils/Config/Config.h"
#include "Utils/Logging/Log.h"
#include "Utils/SteamMetadata/SteamDiagnostics.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>
#include <vector>

namespace RemoteToml {

namespace {
    // Built-in mirror chain, tried in order. Used when [remote] url_template is unset.
    // Mirrors are independent repos/hosts (not just CDN copies of one repo).
    constexpr const char* kDefaultTemplates[] = {
        "https://cdn.jsdelivr.net/gh/huanyuejue/steam-monitor@{channel}/{component}/{sha256}.toml",
        "https://gh-proxy.com/https://raw.githubusercontent.com/huanyuejue/steam-monitor/"
        "main/{channel}/{component}/{sha256}.toml"
    };

    static bool HasPlaceholder(std::string_view text, std::string_view placeholder)
    {
        return text.find(placeholder) != std::string_view::npos;
    }

    static bool IsValidTemplate(std::string_view urlTemplate)
    {
        return HasPlaceholder(urlTemplate, "{channel}") &&
               HasPlaceholder(urlTemplate, "{component}") &&
               HasPlaceholder(urlTemplate, "{sha256}");
    }

    static void ReplaceAll(std::string& text,
                           std::string_view from,
                           std::string_view to)
    {
        size_t pos = 0;
        while ((pos = text.find(from, pos)) != std::string::npos) {
            text.replace(pos, from.size(), to);
            pos += to.size();
        }
    }

    static std::string ExpandTemplate(std::string urlTemplate,
                                      const Request& request,
                                      std::string_view sha256)
    {
        ReplaceAll(urlTemplate, "{channel}", request.channel);
        ReplaceAll(urlTemplate, "{component}", request.component);
        ReplaceAll(urlTemplate, "{sha256}", sha256);
        return urlTemplate;
    }

    static std::vector<std::string> BuildUrlTemplates()
    {
        const std::vector<std::string> configured = Config::GetRemoteUrlTemplates();
        if (configured.empty())
            return { std::begin(kDefaultTemplates), std::end(kDefaultTemplates) };

        // A configured list REPLACES the built-ins; keep only valid entries.
        std::vector<std::string> out;
        for (const std::string& tmpl : configured) {
            if (IsValidTemplate(tmpl))
                out.push_back(tmpl);
            else
                LOG_WARN("RemoteToml: remote.url_template entry missing "
                         "{{channel}}/{{component}}/{{sha256}}, skipping: {}", tmpl);
        }
        if (out.empty())
            LOG_WARN("RemoteToml: no valid remote.url_template entries; remote fetch disabled");
        return out;
    }
    // <Steam>/opensteamtool/<channel>/<component>/<sha256>.toml
    // Fetch 和 Invalidate 共用，保证"写的"和"删的"是同一个文件。
    static std::filesystem::path CachePathFor(const Request& request, std::string_view sha256)
    {
        return std::filesystem::path(request.dllPath).parent_path() /
               "opensteamtool" / request.channel / request.component /
               (std::string(sha256) + ".toml");
    }
} // namespace

Result Fetch(const Request& request)
{
    namespace fs = std::filesystem;
    Result out;

    // 1. SHA-256 of the DLL.
    const auto hashStart = std::chrono::steady_clock::now();
    out.sha256 = SteamDiagnostics::Sha256Of(request.dllPath);
    const auto hashMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - hashStart).count();

    if (out.sha256.empty()) {
        LOG_WARN("RemoteToml({}/{}): Sha256OfFile failed for {} ({} ms)",
                 request.channel, request.component, request.dllPath, hashMs);
        return out;
    }
    LOG_INFO("RemoteToml({}/{}): sha256 = {} ({} ms)",
             request.channel, request.component, out.sha256, hashMs);

    // 2. Cache path & dir.
    const fs::path cachePath = CachePathFor(request, out.sha256);
    const fs::path cacheDir  = cachePath.parent_path();
    const std::string cachePathText = cachePath.string();

    std::error_code mkdirEc;
    fs::create_directories(cacheDir, mkdirEc);
    if (mkdirEc) {
        LOG_WARN("RemoteToml({}/{}): could not create cache dir {} ({})",
                 request.channel, request.component, cacheDir.string(), mkdirEc.message());
    }

    // 3. Cache first.
    // 文件按 DLL SHA-256 命名，同一个 SHA 的内容视为不可变，命中就直接用、不发网络请求，
    // 避免远端超时拖慢 hook 安装（2026-11-03 对齐 OpenSteamTool 的做法）。
    // 之前（照搬 HaiphubSteamTool）是远端优先、失败才读缓存：那样 fromCache=true 只代表
    // "远端挂了"，PatternLoader/IPCLoader 的"缓存解析为空 → Invalidate → 重下"自愈就失去前提。
    // 缓存内容真有问题时由调用方 Invalidate 后重新 Fetch，见 PatternLoader.cpp / IPCLoader.cpp。
    {
        std::error_code ec;
        if (fs::exists(cachePath, ec) && !ec) {
            const auto size = fs::file_size(cachePath, ec);
            if (!ec && size > 0) {
                std::ifstream ifs(cachePath, std::ios::binary);
                if (ifs) {
                    std::string buf((std::istreambuf_iterator<char>(ifs)),
                                     std::istreambuf_iterator<char>());
                    if (!buf.empty()) {
                        LOG_INFO("RemoteToml({}/{}): loaded from cache {}",
                                 request.channel, request.component, cachePathText);
                        out.body = std::move(buf);
                        out.ok = true;
                        out.fromCache = true;
                        return out;
                    }
                }
            }
            LOG_WARN("RemoteToml({}/{}): cache file exists but unreadable or empty, going remote: {}",
                     request.channel, request.component, cachePathText);
        }
    }

    // 4. Cache miss → try remote, in url_template array order.
    // 镜像是相互独立的仓库/主机，覆盖范围可能不同，一个 404 不代表其他的也没有，所以总是试下一个。
    // 传输失败（超时/连不上/非 404 的非 200）同一个地址再打一次：跨境链路偶发抖动很常见，一次重试就能救回；
    // 404 不重试，重下也还是没有。重试封顶一次，不在启动路径上烧时间。GET 无副作用，重试是安全的。
    const std::vector<std::string> urlTemplates = BuildUrlTemplates();
    OSTPlatform::Http::Result http;
    std::string lastUrl;
    size_t notFoundCount = 0;

    for (size_t i = 0; i < urlTemplates.size(); ++i) {
        lastUrl = ExpandTemplate(urlTemplates[i], request, out.sha256);
        LOG_INFO("RemoteToml({}/{}): downloading {}",
                 request.channel, request.component, lastUrl);

        http = OSTPlatform::Http::Execute(L"GET", lastUrl.c_str(),
                                          nullptr, 0, nullptr);

        const bool is404   = http.ok && http.status == 404;
        const bool gotBody = http.ok && http.status == 200 && !http.body.empty();
        if (!gotBody && !is404) {
            LOG_INFO("RemoteToml({}/{}): transport failed ({} ok={} HTTP={}), retrying once",
                     request.channel, request.component, lastUrl, http.ok, http.status);
            http = OSTPlatform::Http::Execute(L"GET", lastUrl.c_str(),
                                              nullptr, 0, nullptr);
        }

        if (http.ok && http.status == 200 && !http.body.empty()) break;

        const char* next = (i + 1 < urlTemplates.size()) ? ", trying next" : ", no more mirrors";
        if (http.ok && http.status == 200) {
            LOG_WARN("RemoteToml({}/{}): mirror returned empty body: {}{}",
                     request.channel, request.component, lastUrl, next);
        } else if (http.ok && http.status == 404) {
            ++notFoundCount;
            LOG_WARN("RemoteToml({}/{}): mirror returned HTTP 404: {}{}",
                     request.channel, request.component, lastUrl, next);
        } else {
            LOG_WARN("RemoteToml({}/{}): mirror failed after retry ({} ok={} HTTP={}){}",
                     request.channel, request.component, lastUrl, http.ok, http.status, next);
        }
    }

    // 5. Remote OK → write cache, return body.
    if (http.ok && http.status == 200 && !http.body.empty()) {
        // 先写 .tmp 再改名：写到一半崩溃/断电只会留下 .tmp，不会留下被截断的正式缓存
        // （缓存优先之后，截断的缓存会被一直命中，比没缓存更糟）。
        fs::path tmpPath = cachePath;
        tmpPath += ".tmp";
        std::error_code writeEc;
        {
            std::ofstream ofs(tmpPath, std::ios::binary | std::ios::trunc);
            if (ofs) {
                ofs.write(http.body.data(),
                          static_cast<std::streamsize>(http.body.size()));
                ofs.close();
            }
            if (!ofs)
                writeEc = std::make_error_code(std::errc::io_error);
        }
        if (!writeEc) {
            fs::remove(cachePath, writeEc);   // 目标不存在时 remove 返回 false 但不报错
            if (!writeEc)
                fs::rename(tmpPath, cachePath, writeEc);
        }
        if (writeEc) {
            LOG_WARN("RemoteToml({}/{}): could not write cache {} ({})",
                     request.channel, request.component, cachePathText, writeEc.message());
            std::error_code cleanupEc;
            fs::remove(tmpPath, cleanupEc);
        } else {
            LOG_INFO("RemoteToml({}/{}): cached to {}",
                     request.channel, request.component, cachePathText);
        }
        // 缓存写失败不影响这次使用，下次启动会重新下载。
        out.body = std::move(http.body);
        out.ok = true;
        return out;
    }

    // 6. Total failure — caller handles popup / degraded mode.
    // allNotFound 只给调用方区分日志措辞（全 404 vs 网络问题），不影响是否弹窗。
    // 至少试过一个镜像才算：模板全配错导致一个都没试，属于配置问题，不算全 404。
    out.allNotFound = !urlTemplates.empty() && notFoundCount == urlTemplates.size();
    if (out.allNotFound) {
        LOG_WARN("RemoteToml({}/{}): all {} mirrors returned HTTP 404 (last URL: {})",
                 request.channel, request.component, urlTemplates.size(), lastUrl);
    } else {
        LOG_WARN("RemoteToml({}/{}): no source available (last URL: {} HTTP {})",
                 request.channel, request.component,
                 lastUrl.empty() ? "<none>" : lastUrl, http.status);
    }
    return out;
}

bool Invalidate(const Request& request)
{
    namespace fs = std::filesystem;
    const std::string sha256 = SteamDiagnostics::Sha256Of(request.dllPath);
    if (sha256.empty()) {
        LOG_WARN("RemoteToml({}/{}): Invalidate skipped, Sha256OfFile failed for {}",
                 request.channel, request.component, request.dllPath);
        return false;
    }
    const fs::path cachePath = CachePathFor(request, sha256);
    std::error_code ec;
    const bool removed = fs::remove(cachePath, ec);
    if (ec) {
        LOG_WARN("RemoteToml({}/{}): failed to remove stale cache {} ({})",
                 request.channel, request.component, cachePath.string(), ec.message());
        return false;
    }
    if (removed) {
        LOG_WARN("RemoteToml({}/{}): removed stale cache {}",
                 request.channel, request.component, cachePath.string());
    }
    return removed;
}

} // namespace RemoteToml
