#include "include/Dialog.h"
#include "include/Encoding.h"

#include <windows.h>

namespace OSTPlatform::Dialog {

void ShowWarning(std::string title, std::string message) {
    // 文案是 UTF-8，MessageBoxA 会按系统 ANSI 代码页（中文系统 GBK）解码，
    // 中文必乱码。转 UTF-16 走 MessageBoxW，全 locale 正确显示。
    // 临时量的 c_str 在完整表达式内有效，MessageBoxW 同表达式内用完，安全。
    MessageBoxW(nullptr,
                Encoding::Utf8ToWide(message).c_str(),
                Encoding::Utf8ToWide(title).c_str(),
                MB_OK | MB_ICONWARNING | MB_TOPMOST);
}

} // namespace OSTPlatform::Dialog
