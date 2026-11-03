#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────────────
//  CDKeyReporter —— 激活 CDKey 前调用校验接口（<base_url>/cdkeycheck），并按返回结果写 lua。
//  由 Hooks_NetPacket 在激活请求发出前调用。
//  （2026-10-19 删掉了激活后上报 /cdkeyreport 的 SendReport 和 report_enabled 配置：
//   改成激活前校验后它已经没有调用方，留着只会让人以为上报还在生效。）
// ─────────────────────────────────────────────────────────────────
namespace CDKeyReporter {

    // ── 激活前的机器码校验 ──
    // （2026-10-11 从 {"allow":...} 改成 Steam 响应的字段：激活请求一律拦下，
    //  把接口返回的结果原样造成 Store.RegisterCDKey#1 的响应给界面。）
    // 你的校验接口返回 JSON，字段和 Steam 响应一致，例如：
    //   成功：{"eresult":1,"purchase_result_details":0,"error_message":""}
    //   失败：{"eresult":2,"purchase_result_details":15,"error_message":"key 已被使用"}
    // eresult 对应响应 header 的 eresult（1 = 成功，失败用 2），
    // purchase_result_details 对应响应 body（0 = 无错误，14 = 无效码，15 = 已被使用），
    // error_message 对应响应 header 的 error_message（可选）。
    // 接口成功时返回的 app_info 里的一项，用来补 config/lua 里的 addappid。
    //   "appid":"4001890",
    //   "app_info":[{"app_id":"4001890","is_app":1,"depot_decryption_key":"ea50…"}, …]
    struct LuaApp {
        std::string appId;       // app_id（字符串或数字都行）
        int32_t     isApp = 1;   // is_app，原样写到 addappid 的第二个参数；没给默认 1
        std::string depotKey;    // depot_decryption_key（十六进制）；没给就不写第三个参数
    };

    // 接口返回的 tickets 数组里的一项（2026-10-16 接口改版：之前 token / app_ticket / e_ticket / stat
    // 在顶层、和 appid 同级，现在每个 ticket 带自己的 ticket_id）。
    //   "tickets":[{"ticket_id":"4001890","token":"","app_ticket":"..","e_ticket":"..","stat":".."}, …]
    // 非空的字段写进 <appid>.lua，ticket_id 做第一个参数。
    // ticket_id 不加引号、不校验，其余值原样写进 Lua 字符串且不转义（使用者明确要求）：
    // ticket_id 必须是纯数字；其余值里如果带 " 或换行，生成的 lua 会语法错误，甚至被注入代码，
    // 所以接口必须自己保证值干净、且来源可信。
    struct LuaTicket {
        std::string ticketId;    // → 下面四个函数的第一个参数
        std::string token;       // → addtoken(<ticket_id>, "<token>")
        std::string appTicket;   // → setAppTicket(<ticket_id>, "<app_ticket>")
        std::string eTicket;     // → setETicket(<ticket_id>, "<e_ticket>")
        std::string stat;        // → setStat(<ticket_id>, "<stat>")
    };

    struct CheckResponse {
        bool        httpOk     = false;  // HTTP 请求成功且状态码是 2xx
        uint32_t    httpStatus = 0;      // HTTP 状态码（请求没发出去时为 0）
        int32_t     eresult    = 2;      // 回给 Steam 界面的 eresult；默认 2（Fail）
        int32_t     detail     = 14;     // 回给 Steam 界面的 purchase_result_details；默认 14（无效 key）
        std::string errorMessage;        // 接口返回的 error_message（写进响应 header）
        std::string appId;               // 接口返回的顶层 appid：lua 文件名，也用来判断是否已存在
        std::vector<LuaApp> apps;        // 接口返回的 app_info：lua 文件里每个 app 一行
        std::vector<LuaTicket> tickets;  // 接口返回的 tickets 数组
        bool        isDenuvo   = false;
        bool        isExpiredDenuvo = false;
        bool        isSteamDrm = false;
        // 接口返回的 cdk（2026-11-03 新增）：非空时写注册表 CDKey 用它代替用户输入的 key；
        // 返回 null / 空串 / 没这个字段时保持空，调用方退回用用户输入的 key（见 Hooks_NetPacket.cpp 的 WriteRegistry 调用处）。
        std::string cdk;
        std::string rawBody;             // 接口返回的原始 body，方便排查
    };

    // 激活前同步调用校验接口（在 Steam 网络线程里、激活请求发出之前执行）。
    // 请求 JSON：{"key":"...","steamid":"7656...","machine_id":"..."}
    // 接口连不上、超时、非 2xx、返回里没有 eresult 字段：eresult / detail 保持默认
    // （2 / 14），即按失败处理。
    CheckResponse CheckBeforeActivate(const std::string& key, uint64_t steamId);

    // 校验成功后写 lua：
    //   luaDir 下已经有 <mainAppId>.lua（按文件名判断）：不管里面是什么，先把旧文件备份成
    //     <mainAppId>.lua.bak（已有旧备份就替换），再覆盖成接口返回的内容；备份失败就不覆盖；
    //   没有：扫描其他 .lua，内容里已经出现 mainAppId 就什么都不做，都没有才新建 <mainAppId>.lua。
    // 写入内容是 apps 里每个 app 一行：
    //   有 depotKey：addappid(<app_id>, <is_app>, "<depotKey>")
    //   没有       ：addappid(<app_id>, <is_app>)
    // 之后对 tickets 里每个元素，按非空字段各追加一行（第一个参数是该元素的 ticket_id，不带引号；
    // 第二个参数带引号；ticket_id 为空的元素跳过）：
    //   addtoken(<ticket_id>, "<token>")  setAppTicket(...)  setETicket(...)  setStat(...)
    // 这几行和 addappid 在同一个文件里，所以"别的 .lua 里已出现主 appid 就什么都不做"时它们也不写
    // mainAppId 为空（接口没给顶层 appid）时退回用 apps 里第一个合规的 app_id。
    // depotKey 必须全是十六进制（最多 128 位），不合规的 app 只写日志、跳过
    // （防止接口返回 "../x" 变成路径穿越，或返回带引号的内容变成 Lua 代码注入）。
    void EnsureLuaForApps(const std::string& luaDir, const std::string& mainAppId,
                          const std::vector<LuaApp>& apps, const std::vector<LuaTicket>& tickets);

    //app Denuvo信息写入注册表 
    // mainAppId 不是 1~10 位纯数字（或超出 uint32）时只写日志、不写注册表。
    void WriteRegistry(const std::string& mainAppId, bool isDenuvo, bool isExpiredDenuvo, bool isSteamDrm, const std::string& cdkey);

    // 启动 Denuvo 游戏时拿激活时记下的 cdkey 去 <BaseUrl>/getTicketByCdkey 换票（每次启动都调），
    // 返回的 AppTicket / ETicket 和注册表不一样时，把 AppTicket / ETicket / SteamID / AppTicketExpTime
    // 整套写进 HKCU\Software\Valve\Steam\Apps\<appId>；两张都一样就不写，同样返回 true。
    // 同步阻塞调用方，最长约 2+3+3+10 秒（各阶段超时之和）。BaseUrl 没配、HTTP 失败、
    // 响应里没有这个 appid 或票不是合法十六进制时返回 false，只写日志。
    // （2026-10-21 从 Hooks_Misc.cpp 挪过来：要用本文件里的 JsonEscape / BuildHeaders，它们不对外。）
    bool FetchTicketsByCdkey(uint32_t appId, const std::string& cdkey, uint64_t steamId);

    // 兜底：注册表里三个 DRM 标记都没有时（正常应在 /cdkeycheck 成功后由 WriteRegistry 写好），
    // POST <BaseUrl>/appinfo {"appid":"<appId>"}，把 data.isDenuvo / isExpiredDenuvo / isSteamDrm
    // 写进注册表（不碰 CDKey）并通过出参返回。HTTP 非 200 或 code != 0 返回 false，不写注册表、出参不改。
    bool FetchAppInfo(uint32_t appId, bool& isDenuvo, bool& isExpiredDenuvo, bool& isSteamDrm);

    // SteamDrm 游戏换票：POST <BaseUrl>/appticket {"appid":"<appId>"}，把 ticket.ticket_hex 写进 AppTicket、
    // ticket.steamId 写进 SteamID、ticket.expires_at 写进 AppTicketExpTime（null 就不写），ETicket 不动；
    // 然后把 <luaDir>\<appId>.lua 里 setAppTicket(<appId>, "...") 的第二个参数换成新票
    // （有这一行就替换，没有就追加，没有这个文件就不新建——2026-10-24 和使用者确认）。
    // 要改 lua 是因为 lua 加载时 setAppTicket 会把票写回注册表，不改的话下次 lua 重载会用旧票覆盖新票。
    bool FetchAppTicket(uint32_t appId, const std::string& luaDir);

    // 本机机器码：读注册表 HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    // （Windows 安装时生成，重装系统会变）。读不到时返回空字符串。
    std::string GetMachineId();

    // 日志用：只显示 key 的最后 5 位。
    std::string MaskKey(const std::string& key);

} // namespace CDKeyReporter
