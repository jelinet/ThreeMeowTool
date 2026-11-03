#include "CDKeyReporter.h"

#include "OSTPlatform/include/Http.h"
#include "Utils/Config/Config.h"
#include "Utils/Logging/Log.h"
#include "OSTPlatform/include/SteamCredentialStore.h"
#include "Utils/Tickets/AppTicket.h"
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string_view>
#include <system_error>

// 读注册表里的 MachineGuid 用
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace CDKeyReporter {
namespace {


    constexpr char kCheckPath[]  = "/cdkeycheck";


    std::wstring BuildHeaders(const std::string& authToken) {
        std::wstring h = L"Content-Type: application/json\r\n";
        if (!authToken.empty()) {
            h += L"Authorization: Bearer ";
            h.append(authToken.begin(), authToken.end());
            h += L"\r\n";
        }
        return h;
    }


    // 转义 JSON 字符串中的特殊字符。
    std::string JsonEscape(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 2);
        for (unsigned char c : s) {
            switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
            }
        }
        return out;
    }

    // ── 解析接口返回的 JSON（手写，不加依赖）──
    // 限制：只取第一次出现的同名字段，不区分嵌套对象；不解码 \uXXXX（原样保留）。

    // 找到 "name" 后面冒号之后第一个非空白字符的位置，找不到返回 npos。
    size_t FindValue(const std::string& json, const char* name) {
        const std::string needle = std::string("\"") + name + "\"";
        size_t pos = json.find(needle);
        if (pos == std::string::npos) return std::string::npos;
        pos = json.find_first_not_of(" \t\r\n", pos + needle.size());
        if (pos == std::string::npos || json[pos] != ':') return std::string::npos;
        return json.find_first_not_of(" \t\r\n", pos + 1);
    }

    // 读取整数字段，也兼容写成字符串的数字（"1"）。
    bool GetInt(const std::string& json, const char* name, int32_t& out) {
        size_t pos = FindValue(json, name);
        if (pos == std::string::npos) return false;
        if (json[pos] == '"') ++pos;
        bool neg = false;
        if (pos < json.size() && json[pos] == '-') { neg = true; ++pos; }
        if (pos >= json.size() || json[pos] < '0' || json[pos] > '9') return false;
        int64_t v = 0;
        while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
            v = v * 10 + (json[pos++] - '0');
            if (v > INT32_MAX) return false;
        }
        out = static_cast<int32_t>(neg ? -v : v);
        return true;
    }

    // 读取字符串字段，处理常见转义（\" \\ \/ \n \r \t）。
    bool GetString(const std::string& json, const char* name, std::string& out) {
        size_t pos = FindValue(json, name);
        if (pos == std::string::npos || json[pos] != '"') return false;
        out.clear();
        for (++pos; pos < json.size(); ++pos) {
            char c = json[pos];
            if (c == '"') return true;
            if (c == '\\' && pos + 1 < json.size()) {
                char e = json[++pos];
                switch (e) {
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': out += "\\u"; break;   // 不解码，原样保留
                default:  out += e;      break;  // \" \\ \/
                }
            } else {
                out += c;
            }
        }
        return false;   // 字符串没有结束引号
    }

    // 读取字符串字段；值写成裸数字（如 "token":123）时也接受，按原文取出。
    // 用于 token / stat 这类接口可能返回数字的字段；空串和找不到都返回 false。
    bool GetStringOrNumber(const std::string& json, const char* name, std::string& out) {
        if (GetString(json, name, out)) return !out.empty();
        const size_t pos = FindValue(json, name);
        if (pos == std::string::npos) return false;
        size_t end = pos;
        while (end < json.size() && (json[end] == '-' || json[end] == '.' ||
                                     (json[end] >= '0' && json[end] <= '9'))) ++end;
        if (end == pos) return false;
        out = json.substr(pos, end - pos);
        return true;
    }

    // 读取布尔字段，只认 true / false。
    bool GetBool(const std::string& json, const char* name, bool& out) {
        size_t pos = FindValue(json, name);
        if (pos == std::string::npos) return false;
        if (json.compare(pos, 4, "true") == 0)  { out = true;  return true; }
        if (json.compare(pos, 5, "false") == 0) { out = false; return true; }
        return false;
    }

} // namespace

std::string MaskKey(const std::string& key) {
    constexpr size_t kVisible = 5;
    if (key.size() <= kVisible) return std::string(key.size(), '*');
    return std::string(key.size() - kVisible, '*') + key.substr(key.size() - kVisible);
}

std::string GetMachineId() {
    // 只读一次，之后用缓存（机器码在 Steam 运行期间不会变）。
    static const std::string cached = [] {
        wchar_t buf[128] = {};
        DWORD bytes = sizeof(buf);
        // RRF_SUBKEY_WOW6464KEY：32 位进程也读 64 位注册表视图，
        // 否则 32 位 Steam 里会被重定向，读不到 MachineGuid。
        const LSTATUS st = RegGetValueW(HKEY_LOCAL_MACHINE,
                                        L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                                        RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                                        nullptr, buf, &bytes);
        if (st != ERROR_SUCCESS) {
            LOG_REGISTERCDKEY_DEBUG("CDKey: failed to read MachineGuid ({})", static_cast<long>(st));
            return std::string();
        }
        // MachineGuid 是 GUID 字符串，只有 ASCII，直接逐字符转换。
        std::string out;
        for (const wchar_t* p = buf; *p; ++p) out += static_cast<char>(*p);
        return out;
    }();
    return cached;
}

namespace {

    // 遍历顶层数组字段 arrayKey 里的每个 {...} 对象，对每个对象的原文调用 fn。
    // depot_key 和 tickets 两个数组共用，避免括号配对逻辑写两份。
    template <typename Fn>
    void ForEachObjectInArray(const std::string& json, const char* arrayKey, Fn fn) {
        const size_t start = FindValue(json, arrayKey);
        if (start == std::string::npos || json[start] != '[') return;

        size_t i = start + 1;
        while (i < json.size()) {
            i = json.find_first_not_of(" \t\r\n,", i);
            if (i == std::string::npos || json[i] != '{') break;   // ']' 或格式不对都结束

            // 找和 '{' 配对的 '}'，跳过字符串里的括号和转义。
            size_t j = i;
            int depth = 0;
            bool inStr = false;
            for (; j < json.size(); ++j) {
                const char ch = json[j];
                if (inStr) {
                    if (ch == '\\') ++j;
                    else if (ch == '"') inStr = false;
                } else if (ch == '"') {
                    inStr = true;
                } else if (ch == '{') {
                    ++depth;
                } else if (ch == '}') {
                    if (--depth == 0) break;
                }
            }
            if (j >= json.size()) break;   // 没找到配对的 '}'

            fn(json.substr(i, j - i + 1));
            i = j + 1;
        }
    }

    std::vector<LuaApp> ParseAppInfo(const std::string& json) {
        std::vector<LuaApp> apps;
        ForEachObjectInArray(json, "depot_key", [&](const std::string& obj) {
            LuaApp app;
            if (!GetString(obj, "app_id", app.appId)) {
                int32_t id = 0;
                if (GetInt(obj, "app_id", id)) app.appId = std::to_string(id);
            }
            int32_t isApp = 1;
            if (GetInt(obj, "is_app", isApp)) app.isApp = isApp;
            GetString(obj, "depot_decryption_key", app.depotKey);
            apps.push_back(std::move(app));
        });
        return apps;
    }

    // tickets 数组：每个元素一个 ticket_id + 四个可选字段（2026-10-16 接口改版，
    // 之前这四个字段在顶层、和 appid 同级）。缺失 / 为空 / 不是字符串或数字都保持空。
    std::vector<LuaTicket> ParseTickets(const std::string& json) {
        std::vector<LuaTicket> tickets;
        ForEachObjectInArray(json, "tickets", [&](const std::string& obj) {
            LuaTicket t;
            GetStringOrNumber(obj, "ticket_id", t.ticketId);
            GetStringOrNumber(obj, "token", t.token);
            GetStringOrNumber(obj, "app_ticket", t.appTicket);
            GetStringOrNumber(obj, "e_ticket", t.eTicket);
            GetStringOrNumber(obj, "stat", t.stat);
            tickets.push_back(std::move(t));
        });
        return tickets;
    }

}

CheckResponse CheckBeforeActivate(const std::string& key, uint64_t steamId) {
    // 步骤 1：组装请求 JSON（TODO: 需要别的字段就在这里加），同步 POST 到校验接口。
    std::string body = "{\"key\":\"" + JsonEscape(key) + "\"";
    body += ",\"steamid\":\"" + std::to_string(steamId) + "\"";
    body += ",\"machine_id\":\"" + JsonEscape(GetMachineId()) + "\"}";
    const Config::CdkeySettings cfg = Config::GetCdkeySettings();
    const std::wstring headers = BuildHeaders(cfg.authToken);
    // 调用方（Hooks_NetPacket）已保证 base_url 非空才会走到这里；热加载在两者之间把它清空的话，
    // 拼出来的 "/cdkeycheck" 不是合法 URL，Execute 会失败并走下面的失败分支，不会崩。
    const std::string checkUrl = cfg.baseUrl + kCheckPath;
    auto res = OSTPlatform::Http::Execute(L"POST", checkUrl.c_str(),
                                          body.data(), static_cast<uint32_t>(body.size()),
                                          headers.c_str(),
                                          cfg.timeoutMs, cfg.timeoutMs, cfg.timeoutMs, cfg.timeoutMs);

    CheckResponse out;
    out.httpStatus = res.status;
    out.httpOk     = res.ok && res.status >= 200 && res.status < 300;
    out.rawBody    = res.body;
    // 2026-10-14 原来是把整个 CheckResponse 传给日志：fmt 没有它的格式化器，编译不过
    // （type_is_unformattable_for），而且那时 out 还没填值。改成记 HTTP 状态和响应原文。
    // 请求 URL、请求参数、返回结果合成一条，方便对照（2026-10-14 使用者要求）。
    // 注意：请求参数是完整的 key 和机器码，返回里可能有 token/ticket，没打码；排查完建议删掉这条。
    LOG_REGISTERCDKEY_DEBUG("CDKey check url={} request={} status={} ok={} response={}",
                            checkUrl, body, res.status, res.ok, res.body);

    // 步骤 2：HTTP 失败（网络错误、超时、非 2xx）按失败处理：eresult / detail 保持默认 2 / 14。
    if (!out.httpOk) {
        LOG_REGISTERCDKEY_DEBUG("CDKey check failed key={} status={} ok={} -> fail",
                           MaskKey(key), res.status, res.ok);
        return out;
    }

    // 步骤 3：解析 eresult。没有 eresult 字段也按失败处理（保持默认 2 / 14）。
    int32_t eresult = 0;
    if (!GetInt(res.body, "eresult", eresult)) {
        LOG_REGISTERCDKEY_DEBUG("CDKey check key={} response has no eresult, body={} -> fail",
                           MaskKey(key), res.body);
        return out;
    }
    out.eresult = eresult;

    // 步骤 4：读取 purchase_result_details、error_message 和 app_id（都是可选字段）。
    // app_id 兼容写成字符串（"367520"）或数字（367520）。
    // 成功（eresult == 1）时 detail 默认 0；失败时没给就保持 14。
    if (eresult == 1) out.detail = 0;
    int32_t detail = 0;
    if (GetInt(res.body, "purchase_result_details", detail)) out.detail = detail;
    GetString(res.body, "error_message", out.errorMessage);
    // 顶层 appid 兼容字符串和数字。
    if (!GetString(res.body, "appid", out.appId)) {
        int32_t id = 0;
        if (GetInt(res.body, "appid", id)) out.appId = std::to_string(id);
    }
    out.apps = ParseAppInfo(res.body);
    out.tickets = ParseTickets(res.body);
    out.isDenuvo = false;
    GetBool(res.body, "isDenuvo", out.isDenuvo);
    out.isExpiredDenuvo = false;
    GetBool(res.body, "isExpiredDenuvo", out.isExpiredDenuvo);
    out.isSteamDrm = false;
    GetBool(res.body, "isSteamDrm", out.isSteamDrm);
    // "cdk":null 时 GetString 返回 false（值不是以 " 开头），out.cdk 保持空串，和没给这个字段等价。
    GetString(res.body, "cdk", out.cdk);

    LOG_REGISTERCDKEY_DEBUG("CDKey check key={} eresult={} detail={} error_message={} appid={} apps={} tickets={} isDenuvo={} isExpiredDenuvo={} isSteamDrm={} cdk={}",
                       MaskKey(key), out.eresult, out.detail, out.errorMessage, out.appId, out.apps.size(),
                       out.tickets.size(), out.isDenuvo, out.isExpiredDenuvo, out.isSteamDrm, MaskKey(out.cdk));
    return out;
}

namespace {

    // text 里是否出现 appId，并且前后都不是数字（避免 36752 误匹配 367520）。
    // 这里是宽松匹配：addappid(...) 里的、别的函数里的、被注释掉的都算出现过
    // （2026-10-12 和使用者确认保持这样）。
    bool ContainsAppId(const std::string& text, const std::string& appId) {
        for (size_t pos = text.find(appId); pos != std::string::npos; pos = text.find(appId, pos + 1)) {
            const bool leftOk  = pos == 0 || text[pos - 1] < '0' || text[pos - 1] > '9';
            const size_t end   = pos + appId.size();
            const bool rightOk = end >= text.size() || text[end] < '0' || text[end] > '9';
            if (leftOk && rightOk) return true;
        }
        return false;
    }

    bool IsDigits(const std::string& s, size_t maxLen) {
        return !s.empty() && s.size() <= maxLen && s.find_first_not_of("0123456789") == std::string::npos;
    }

    bool IsHex(const std::string& s, size_t maxLen) {
        return !s.empty() && s.size() <= maxLen &&
               s.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
    }

}

void EnsureLuaForApps(const std::string& luaDir, const std::string& mainAppId,
                      const std::vector<LuaApp>& apps, const std::vector<LuaTicket>& tickets) {
    namespace fs = std::filesystem;

    // 步骤 1：过滤不合规的 app（理由见 CDKeyReporter.h），剩下的才可能被写进文件。
    std::vector<const LuaApp*> valid;
    for (const LuaApp& app : apps) {
        if (!IsDigits(app.appId, 10)) {
            LOG_REGISTERCDKEY_DEBUG("CDKey lua: invalid app_id '{}', skip", app.appId);
            continue;
        }
        if (!app.depotKey.empty() && !IsHex(app.depotKey, 128)) {
            LOG_REGISTERCDKEY_DEBUG("CDKey lua: app_id {} has invalid depot_decryption_key, skip", app.appId);
            continue;
        }
        valid.push_back(&app);
    }
    if (valid.empty()) return;

    // 步骤 2：确定"主 appid"（文件名 + 是否已存在的判断依据）。
    // 接口没给顶层 appid 时退回第一个合规的 app_id；给了但不合规就整个跳过。
    std::string mainId = mainAppId;
    if (mainId.empty()) mainId = valid.front()->appId;
    if (!IsDigits(mainId, 10)) {
        LOG_REGISTERCDKEY_DEBUG("CDKey lua: invalid appid '{}', skip", mainId);
        return;
    }

    std::error_code ec;
    const fs::path dir(luaDir);
    fs::create_directories(dir, ec);   // 目录已存在不算错误

    // 步骤 3：<主 appid>.lua 已经存在（按文件名判断）就直接用接口的内容覆盖，不管里面原来是什么
    // （2026-10-12 和使用者确认方案 A）。这样接口更新了 key 或 app 列表，下次激活能刷新文件。
    // 覆盖是幂等的：内容完全由接口返回决定，重复执行结果一样。
    // 之前的版本是"任何 .lua 里出现过主 appid 就什么都不做"，会让自己写的 <appid>.lua 永远刷新不了，
    // 所以改成先看同名文件。
    const fs::path target = dir / (mainId + ".lua");
    const bool overwrite = fs::exists(target, ec);

    // 步骤 4：同名文件不存在时，才扫描其他 .lua：内容里出现过主 appid（别的文件已经加过）
    // 就什么都不做，避免重复 addappid；都没有才新建。
    if (!overwrite) {
        for (fs::directory_iterator it(dir, ec), endIt; !ec && it != endIt; it.increment(ec)) {
            std::error_code fe;
            if (!it->is_regular_file(fe) || fe) continue;
            std::string ext = it->path().extension().string();
            for (char& ch : ext) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            if (ext != ".lua") continue;

            std::ifstream in(it->path(), std::ios::binary);
            if (!in) continue;
            const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            if (ContainsAppId(text, mainId)) {
                LOG_REGISTERCDKEY_DEBUG("CDKey lua: appid {} already in {}, nothing to do",
                                   mainId, it->path().filename().string());
                return;
            }
        }
    }

    // 步骤 5：写 <主 appid>.lua，每个 app 一行，后面接各 ticket 的 token / ticket / stat。
    std::string content;
    for (const LuaApp* app : valid) {
        content += "addappid(" + app->appId + ", " + std::to_string(app->isApp);
        if (!app->depotKey.empty()) content += ", \"" + app->depotKey + "\"";
        content += ")\n";
    }
    // 每个 ticket 用自己的 ticket_id 做第一个参数（不加引号、不校验，2026-10-16 使用者明确要求，
    // 风险见 LuaTicket 的说明）；第二个参数同样原样写。ticket_id 为空没法写首参，跳过并记日志；
    // 四个字段都为空的元素自然不产生任何行。
    for (const LuaTicket& t : tickets) {
        if (t.ticketId.empty()) {
            LOG_REGISTERCDKEY_DEBUG("CDKey lua: ticket without ticket_id, skip");
            continue;
        }
        const auto appendExtra = [&](const char* func, const std::string& value) {
            if (!value.empty()) content += std::string(func) + "(" + t.ticketId + ", \"" + value + "\")\n";
        };
        appendExtra("addtoken", t.token);
        appendExtra("setAppTicket", t.appTicket);
        appendExtra("setETicket", t.eTicket);
        appendExtra("setStat", t.stat);
    }
    // 先写成 .tmp 再改名：lua 目录有文件监视（LuaFileWatcher），直接写 .lua 的话
    // 可能读到写了一半的内容；.tmp 不是 .lua，监视不会处理。
    const fs::path tmp = dir / (mainId + ".lua.tmp");
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            LOG_REGISTERCDKEY_DEBUG("CDKey lua: cannot create {}", tmp.string());
            return;
        }
        out << content;
        if (!out.good()) {
            LOG_REGISTERCDKEY_DEBUG("CDKey lua: write failed {}", tmp.string());
            return;
        }
    }
    // 覆盖前先把旧文件备份成 <原文件名>.bak（即 <主 appid>.lua.bak，2026-10-12 和使用者确认）。
    // 已有旧的 .bak 就被这次的替换，只保留最近一次的备份。
    // 用"复制"而不是"改名"：改名会让 .lua 在两步之间短暂不存在，LuaFileWatcher 可能把它当成
    // 删除处理；复制之后原文件一直在，直到下面的 rename 一步换成新内容。
    // 备份失败就放弃覆盖：宁可这次不更新，也不能在没有备份的情况下丢掉原内容。
    if (overwrite) {
        const fs::path bak = dir / (mainId + ".lua.bak");
        fs::copy_file(target, bak, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            LOG_REGISTERCDKEY_DEBUG("CDKey lua: backup to {} failed ({}), not overwriting",
                               bak.string(), ec.message());
            fs::remove(tmp, ec);
            return;
        }
        LOG_REGISTERCDKEY_DEBUG("CDKey lua: backed up old file to {}", bak.string());
    }
    // rename 在目标已存在时会替换它（Windows 上 std::filesystem::rename 用的是
    // MOVEFILE_REPLACE_EXISTING），所以覆盖和新建走同一段代码；监视器看到的永远是完整的新内容。
    fs::rename(tmp, target, ec);
    if (ec) {
        LOG_REGISTERCDKEY_ERROR("CDKey lua: rename to {} failed ({})", target.string(), ec.message());
        fs::remove(tmp, ec);
        return;
    }
    LOG_REGISTERCDKEY_INFO("CDKey lua: {} {} ({} apps)",
                       overwrite ? "overwrote" : "created", target.string(), valid.size());
}
//app Denuvo信息写入注册表 
void WriteRegistry(const std::string& mainAppId, bool isDenuvo, bool isExpiredDenuvo, bool isSteamDrm, const std::string& cdkey) {
    // appid 来自接口返回的字符串，WriteDenuvoFlag 要 uint32_t；解析不了就不写，免得写进 Apps\0。
    uint32_t appId = 0;
    const char* first = mainAppId.data();
    const char* last  = first + mainAppId.size();
    const auto [ptr, ec] = std::from_chars(first, last, appId);
    if (mainAppId.empty() || ec != std::errc() || ptr != last || appId == 0) {
        LOG_REGISTERCDKEY_ERROR("CDKey DenuvoFlag: invalid appid \"{}\", skip writing registry", mainAppId);
        return;
    }

    const auto status = OSTPlatform::SteamCredentialStore::WriteDenuvoFlag(appId, isDenuvo, isExpiredDenuvo, isSteamDrm, cdkey);
    // 注册表里必须存原文：之后 FetchTicketsByCdkey 拿它去服务端换票，存打码值会换票失败。打码只用于日志。
    if (status != OSTPlatform::SteamCredentialStore::Status::Ok) {
        LOG_REGISTERCDKEY_ERROR("CDKey Failed to write DenuvoFlag for AppId {} isDenuvo={} isExpiredDenuvo={} isSteamDrm={} cdkey={} to Registry: {}",
                                appId, isDenuvo, isExpiredDenuvo, isSteamDrm, MaskKey(cdkey), OSTPlatform::SteamCredentialStore::ToString(status));
        return;
    }

    LOG_REGISTERCDKEY_INFO("CDKey Successfully wrote DenuvoFlag for AppId {} isDenuvo={} isExpiredDenuvo={} isSteamDrm={} cdkey={} to Registry",
                           appId, isDenuvo, isExpiredDenuvo, isSteamDrm, MaskKey(cdkey));
}

namespace {

    // 同 TokeerBridge.cpp 的 HexToBytes（那份在它的匿名命名空间里，拿不到）。
    int HexNibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    std::optional<std::vector<uint8_t>> HexToBytes(std::string_view hex) {
        if (hex.empty() || (hex.size() % 2) != 0) return std::nullopt;
        std::vector<uint8_t> out;
        out.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            const int hi = HexNibble(hex[i]);
            const int lo = HexNibble(hex[i + 1]);
            if (hi < 0 || lo < 0) return std::nullopt;
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        return out;
    }

    // 从 openBrace 开始截取一个 {...} 平衡括号块，返回该块的 string_view
    std::string_view JsonBlock(std::string_view body, size_t openBrace) {
        if (openBrace == std::string_view::npos || openBrace >= body.size() || body[openBrace] != '{') return {};
        int depth = 0;
        for (size_t i = openBrace; i < body.size(); ++i) {
            if (body[i] == '{') ++depth;
            else if (body[i] == '}') {
                if (--depth == 0) return body.substr(openBrace, i - openBrace + 1);
            }
        }
        return {};
    }

    // 在 scope 里找 "key": { ... } 对应的子对象块
    std::string_view JsonObjectValue(std::string_view scope, std::string_view key) {
        const std::string needle = "\"" + std::string(key) + "\"";
        size_t k = scope.find(needle);
        if (k == std::string_view::npos) return {};
        size_t brace = scope.find('{', k + needle.size());
        return JsonBlock(scope, brace);
    }

    // 在指定范围内找 "key":"string" 值（基于 TokeerBridge 的 JsonString 改造，加了 scope）
    bool JsonStringIn(std::string_view scope, std::string_view key, std::string& out) {
        const std::string needle = "\"" + std::string(key) + "\"";
        size_t k = scope.find(needle);
        if (k == std::string_view::npos) return false;
        size_t colon = scope.find(':', k + needle.size());
        if (colon == std::string_view::npos) return false;
        size_t q1 = scope.find('"', colon + 1);
        if (q1 == std::string_view::npos) return false;
        size_t q2 = scope.find('"', q1 + 1);
        if (q2 == std::string_view::npos) return false;
        out = std::string(scope.substr(q1 + 1, q2 - q1 - 1));
        return true;
    }

    // 读 "key": <整数>，值是 null / 缺失 / 不是数字都返回 false。expires_at 是 Unix 秒，
    // 2038 年后会超出 int32，所以不用上面的 GetInt。
    bool JsonUInt64In(std::string_view scope, std::string_view key, uint64_t& out) {
        const std::string needle = "\"" + std::string(key) + "\"";
        size_t k = scope.find(needle);
        if (k == std::string_view::npos) return false;
        size_t colon = scope.find(':', k + needle.size());
        if (colon == std::string_view::npos) return false;
        size_t v = scope.find_first_not_of(" \t\r\n\"", colon + 1);
        if (v == std::string_view::npos || scope[v] < '0' || scope[v] > '9') return false;   // null 走这里
        uint64_t value = 0;
        const auto [ptr, ec] = std::from_chars(scope.data() + v, scope.data() + scope.size(), value);
        if (ec != std::errc()) return false;
        out = value;
        return true;
    }

    // 把 ticket 对象 {"ticket_hex":..,"steamId":..,"expires_at":..} 写进注册表：
    // AppTicket（必须有且是合法十六进制）、SteamID（没有就从票里解析）、AppTicketExpTime（null 就不写）。
    // outHex 非空时带回 ticket_hex 原文，给 lua 用（已经过 HexToBytes 校验，只含十六进制字符，可以直接拼进 lua 字符串）。
    // 重复调用是安全的：全是覆盖写同一组值。
    bool WriteAppTicketObject(std::string_view tObj, uint32_t appId, std::string* outHex) {
        namespace CS = OSTPlatform::SteamCredentialStore;
        std::string appHex, appSid;
        if (!JsonStringIn(tObj, "ticket_hex", appHex)) return false;
        JsonStringIn(tObj, "steamId", appSid);   // steamId 缺失也能容忍，从票里解析

        auto appTicket = HexToBytes(appHex);
        if (!appTicket) return false;
        if (CS::WriteAppTicket(appId, *appTicket) != CS::Status::Ok) return false;

        // steamId：优先用响应里的；没有就从 appticket 里解析（必须与票内一致）
        uint64_t sid = appSid.empty() ? AppTicket::ExtractSteamIdFromTicketBytes(*appTicket)
                                      : std::strtoull(appSid.c_str(), nullptr, 10);
        if (sid != 0) CS::WriteSteamId(appId, sid);

        uint64_t expiresAt = 0;
        if (JsonUInt64In(tObj, "expires_at", expiresAt)) {
            const auto st = CS::WriteAppTicketExpTime(appId, expiresAt);
            LOG_REGISTERCDKEY_INFO("CDKey AppTicketExpTime appid={} expires_at={} ({})", appId, expiresAt, CS::ToString(st));
        } else {
            LOG_REGISTERCDKEY_INFO("CDKey AppTicketExpTime appid={}: expires_at null/missing, not written", appId);
        }

        if (outHex) *outHex = std::move(appHex);
        return true;
    }

    // 在 data.tickets 数组里找 appid == wantAppId 的元素，找不到返回空。
    std::string_view FindTicketItem(std::string_view body, uint32_t wantAppId) {
        size_t arrPos = body.find("\"tickets\"");
        if (arrPos == std::string_view::npos) return {};
        size_t scan = body.find('[', arrPos);
        while (scan != std::string_view::npos &&
               (scan = body.find('{', scan)) != std::string_view::npos) {
            std::string_view item = JsonBlock(body, scan);
            if (item.empty()) return {};
            scan += item.size();
            uint64_t id = 0;
            if (JsonUInt64In(item, "appid", id) && id == wantAppId) return item;
        }
        return {};
    }

    // 把 <luaDir>\<appId>.lua 里 setAppTicket(<appId>, "...") 的第二个参数换成 hex。
    // 有这一行就替换（大小写不敏感，lua 里 setappticket 也注册了），没有就追加，没有这个文件就不新建。
    // 同 EnsureLuaForApps：先写 .tmp 再 rename，LuaFileWatcher 不会读到写一半的文件。
    void UpdateLuaAppTicket(const std::string& luaDir, uint32_t appId, const std::string& hex) {
        namespace fs = std::filesystem;
        std::error_code ec;
        const std::string id = std::to_string(appId);
        const fs::path target = fs::path(luaDir) / (id + ".lua");
        if (!fs::exists(target, ec)) {
            LOG_REGISTERCDKEY_INFO("CDKey lua: {} not found, setAppTicket not updated", target.string());
            return;
        }
        std::string content;
        {
            std::ifstream in(target, std::ios::binary);
            if (!in) {
                LOG_REGISTERCDKEY_ERROR("CDKey lua: cannot read {}", target.string());
                return;
            }
            content.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }

        const std::string newLine = "setAppTicket(" + id + ", \"" + hex + "\")";
        std::string out;
        bool replaced = false;
        size_t pos = 0;
        while (pos < content.size()) {
            size_t eol = content.find('\n', pos);
            const size_t end = (eol == std::string::npos) ? content.size() : eol;
            std::string_view line(content.data() + pos, end - pos);
            const bool cr = !line.empty() && line.back() == '\r';   // 保留原来的 CRLF

            // 去掉行首空白后看是不是 setAppTicket(<appId>, ...)
            size_t p = line.find_first_not_of(" \t");
            bool match = false;
            if (p != std::string_view::npos && line.size() - p > 13) {
                std::string head(line.substr(p, 13));
                for (char& c : head) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (head == "setappticket(") {
                    size_t a = line.find_first_not_of(" \t", p + 13);
                    size_t b = line.find_first_of(", \t)", a);
                    match = a != std::string_view::npos && b != std::string_view::npos && line.substr(a, b - a) == id;
                }
            }
            if (match) {
                out += newLine;
                if (cr) out += '\r';
                replaced = true;
            } else {
                out.append(line.data(), line.size());
            }
            if (eol != std::string::npos) out += '\n';
            pos = (eol == std::string::npos) ? content.size() : eol + 1;
        }
        if (!replaced) {
            if (!out.empty() && out.back() != '\n') out += '\n';
            out += newLine + "\n";
        }

        const fs::path tmp = fs::path(luaDir) / (id + ".lua.tmp");
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) {
                LOG_REGISTERCDKEY_ERROR("CDKey lua: cannot create {}", tmp.string());
                return;
            }
            f << out;
            if (!f.good()) {
                LOG_REGISTERCDKEY_ERROR("CDKey lua: write failed {}", tmp.string());
                return;
            }
        }
        fs::rename(tmp, target, ec);
        if (ec) {
            LOG_REGISTERCDKEY_ERROR("CDKey lua: rename to {} failed ({})", target.string(), ec.message());
            fs::remove(tmp, ec);
            return;
        }
        LOG_REGISTERCDKEY_INFO("CDKey lua: {} setAppTicket in {}", replaced ? "replaced" : "appended", target.string());
    }

    // POST <BaseUrl><path>，body 为 {"appid":"<appId>"}。/appinfo 和 /appticket 共用。
    // BaseUrl 没配、HTTP 失败、非 200、code != 0 都返回 false。
    bool PostAppId(const char* path, uint32_t appId, std::string& body) {
        const Config::CdkeySettings cfg = Config::GetCdkeySettings();
        if (cfg.baseUrl.empty()) {
            LOG_REGISTERCDKEY_WARN("CDKey {} skipped appid={}: BaseUrl not set", path, appId);
            return false;
        }
        const std::string url = cfg.baseUrl + path;
        const std::string reqBody = "{\"appid\":\"" + std::to_string(appId) + "\"}";
        const std::wstring headers = BuildHeaders(cfg.authToken);
        // 超时同 FetchTicketsByCdkey：都在启动游戏的线程里同步跑，卡启动的上限。
        OSTPlatform::Http::Result r = OSTPlatform::Http::Execute(
            L"POST", url.c_str(),
            reqBody.data(), static_cast<uint32_t>(reqBody.size()),
            headers.c_str(),
            2000, 3000, 3000, 10000,
            4u * 1024 * 1024);
        LOG_REGISTERCDKEY_INFO("CDKey {} appid={} ok={} status={} body={}", path, appId, r.ok, r.status, r.body);
        if (!r.ok || r.status != 200) return false;
        int32_t code = -1;
        if (!GetInt(r.body, "code", code) || code != 0) return false;
        body = std::move(r.body);
        return true;
    }

    // 响应形如 {"code":0,"message":"ok","data":{"tickets":[{"appid":703080,"ticket":{...},"e_ticket":{...}}]}}
    // 在 tickets 数组里找 appid 匹配的元素，把 AppTicket / ETicket / SteamID 写进注册表。
    // 接口返回的 AppTicket、ETicket 和注册表里的逐字节比较：两张都一样就什么都不写；
    // 有一张不一样就整套重写（AppTicket + ETicket + SteamID + AppTicketExpTime），
    // 不单独替换某一张，免得新 AppTicket 配旧 SteamID / 过期时间（2026-10-25 和使用者确认）。
    // 两种情况都返回 true（接口成功）；接口内容不合法才返回 false。
    bool WriteTicketsFromResponse(std::string_view body, uint32_t wantAppId) {
        namespace CS = OSTPlatform::SteamCredentialStore;

        const std::string_view item = FindTicketItem(body, wantAppId);
        if (item.empty()) return false;   // 数组里没有这个 appid

        // ── 命中：取 ticket / e_ticket 子对象 ──
        std::string appHex, eHex;
        const std::string_view tObj  = JsonObjectValue(item, "ticket");
        const std::string_view etObj = JsonObjectValue(item, "e_ticket");

        if (!JsonStringIn(tObj,  "ticket_hex", appHex)) return false;
        if (!JsonStringIn(etObj, "ticket_hex", eHex))   return false;
        auto appTicket = HexToBytes(appHex);
        auto eTicket   = HexToBytes(eHex);
        if (!appTicket || !eTicket) return false;

        // 注册表读不到时 Get* 不改出参，保持空 vector，和接口值比较自然算"不一样"。
        std::vector<uint8_t> regAppTicket, regETicket;
        CS::GetAppTicket(wantAppId, regAppTicket);
        CS::GetETicket(wantAppId, regETicket);
        const bool appSame = (regAppTicket == *appTicket);
        const bool eSame   = (regETicket == *eTicket);
        LOG_REGISTERCDKEY_INFO("CDKey ticket compare appid={} appTicketSame={} eTicketSame={}",
                               wantAppId, appSame, eSame);
        if (appSame && eSame) return true;

        // 先验 ETicket 再写 AppTicket：ETicket 不合法时两张票都不写，不留半套。
        // AppTicket / SteamID / AppTicketExpTime 的写法和 /appticket 共用，见 WriteAppTicketObject。
        if (!WriteAppTicketObject(tObj, wantAppId, nullptr)) return false;
        return CS::WriteETicket(wantAppId, *eTicket) == CS::Status::Ok;
    }

} // namespace

bool FetchTicketsByCdkey(uint32_t appId, const std::string& cdkey, uint64_t steamId) {
    LOG_REGISTERCDKEY_INFO("CDKey ticket fetch: appid={} key={} steamid={}",
                           appId, MaskKey(cdkey), steamId);
    const Config::CdkeySettings cfg = Config::GetCdkeySettings();
    if (cfg.baseUrl.empty()) {
        LOG_REGISTERCDKEY_WARN("CDKey ticket fetch skipped appid={}: BaseUrl not set", appId);
        return false;
    }

    const std::string postUrl = cfg.baseUrl + "/getTicketByCdkey";
    std::string reqBody = "{\"cdkey\":\"" + JsonEscape(cdkey) + "\"";
    reqBody += ",\"steamid\":\"" + std::to_string(steamId) + "\"";
    reqBody += "}";
    // 带上 Authorization（BuildHeaders 里有 Content-Type），和 /cdkeycheck 一样。
    const std::wstring headers = BuildHeaders(cfg.authToken);

    LOG_REGISTERCDKEY_INFO("CDKey ticket fetch: url={} appid={} key={} steamid={}",
                           postUrl, appId, MaskKey(cdkey), steamId);
    OSTPlatform::Http::Result r = OSTPlatform::Http::Execute(
        L"POST", postUrl.c_str(),
        reqBody.data(), static_cast<uint32_t>(reqBody.size()),
        headers.c_str(),
        2000,    // resolve
        3000,    // connect
        3000,    // send
        10000,   // recv —— 卡启动的代价上限，别超过这个
        4u * 1024 * 1024);  // 最大响应体
    LOG_REGISTERCDKEY_INFO("CDKey ticket fetch response appid={} ok={} status={} body={}",
                           appId, r.ok, r.status, r.body);

    if (!r.ok || r.status != 200) {
        LOG_REGISTERCDKEY_WARN("CDKey ticket fetch failed appid={} ok={} status={} body={}",
                               appId, r.ok, r.status, r.body);
        return false;
    }
    if (!WriteTicketsFromResponse(r.body, appId)) {
        LOG_REGISTERCDKEY_WARN("CDKey ticket parse/write failed appid={} body={}", appId, r.body);
        return false;
    }
    LOG_REGISTERCDKEY_INFO("CDKey ticket fetch success appid={}", appId);
    return true;
}

bool FetchAppInfo(uint32_t appId, bool& isDenuvo, bool& isExpiredDenuvo, bool& isSteamDrm) {
    std::string body;
    if (!PostAppId("/appinfo", appId, body)) {
        LOG_REGISTERCDKEY_WARN("CDKey appinfo failed appid={}, flags not written", appId);
        return false;
    }
    // 三个字段都只在 data 里出现一次，GetBool 取第一次出现即可；缺的字段按 false。
    bool d = false, e = false, s = false;
    GetBool(body, "isDenuvo", d);
    GetBool(body, "isExpiredDenuvo", e);
    GetBool(body, "isSteamDrm", s);

    const auto st = OSTPlatform::SteamCredentialStore::WriteDrmFlags(appId, d, e, s);
    LOG_REGISTERCDKEY_INFO("CDKey appinfo appid={} isDenuvo={} isExpiredDenuvo={} isSteamDrm={} write={}",
                           appId, d, e, s, OSTPlatform::SteamCredentialStore::ToString(st));
    isDenuvo = d;
    isExpiredDenuvo = e;
    isSteamDrm = s;
    return true;
}

bool FetchAppTicket(uint32_t appId, const std::string& luaDir) {
    std::string body;
    if (!PostAppId("/appticket", appId, body)) {
        LOG_REGISTERCDKEY_WARN("CDKey appticket request failed appid={}", appId);
        return false;
    }
    const std::string_view item = FindTicketItem(body, appId);
    std::string hex;
    if (item.empty() || !WriteAppTicketObject(JsonObjectValue(item, "ticket"), appId, &hex)) {
        LOG_REGISTERCDKEY_WARN("CDKey appticket parse/write failed appid={}", appId);
        return false;
    }
    UpdateLuaAppTicket(luaDir, appId, hex);
    LOG_REGISTERCDKEY_INFO("CDKey appticket success appid={}", appId);
    return true;
}

} // namespace CDKeyReporter
