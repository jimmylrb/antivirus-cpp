// heuristic.h — 启发式检测：分析文件行为特征，识别未知威胁
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>

namespace av {

// 启发式风险等级
enum class HeuristicLevel { Clean = 0, Suspicious = 1, Malicious = 2 };

// 启发式检测结果
struct HeuristicResult {
    HeuristicLevel level = HeuristicLevel::Clean;
    std::vector<std::string> reasons;  // 命中原因
    int score = 0;                     // 风险评分
};

class HeuristicEngine {
public:
    // 分析文件内容（最多前 2MB）
    HeuristicResult analyze(const std::string& path, const std::vector<uint8_t>& data);

private:
    // 检查 PE 文件（Windows 可执行文件）
    void analyzePe(const std::vector<uint8_t>& data, HeuristicResult& r);
    // 检查危险 API 调用字符串
    void checkSuspiciousStrings(const std::vector<uint8_t>& data, HeuristicResult& r);
    // 检查文件是否打包/加壳（高熵节区）
    void checkPacked(const std::vector<uint8_t>& data, HeuristicResult& r);

    static bool hasAscii(const std::vector<uint8_t>& d, const char* s);
    static double entropy(const uint8_t* p, size_t n);
};

inline bool HeuristicEngine::hasAscii(const std::vector<uint8_t>& d, const char* s) {
    size_t len = strlen(s);
    for (size_t i = 0; i + len <= d.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < len; ++j)
            if (d[i + j] != (uint8_t)s[j]) { match = false; break; }
        if (match) return true;
    }
    return false;
}

inline double HeuristicEngine::entropy(const uint8_t* p, size_t n) {
    if (n == 0) return 0;
    int counts[256] = {0};
    for (size_t i = 0; i < n; ++i) counts[p[i]]++;
    double e = 0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i]) {
            double pr = (double)counts[i] / n;
            e -= pr * log2(pr);
        }
    }
    return e;
}

inline void HeuristicEngine::checkSuspiciousStrings(const std::vector<uint8_t>& data, HeuristicResult& r) {
    // 危险 API / 行为特征（黑客工具与病毒常用）
    static const char* susp[] = {
        "CreateRemoteThread",   // 远程线程注入
        "WriteProcessMemory",   // 写入其他进程内存
        "VirtualAllocEx",       // 远程分配内存
        "SetWindowsHookEx",     // 全局钩子（键盘记录）
        "GetAsyncKeyState",     // 键盘状态读取（键盘记录器）
        "FindFirstFile",        // 枚举文件（蠕虫遍历）
        "RegSetValueEx",        // 写注册表（持久化）
        "WinExec",              // 执行命令
        "ShellExecute",         // 执行程序
        "DeleteFile",           // 删除文件
        "MoveFile",             // 移动文件
        "CryptEncrypt",         // 加密（勒索软件）
        "WinHttpOpen",          // HTTP 通信（C2）
        "URLDownloadToFile",    // 下载文件
        "AdjustTokenPrivileges" // 提权
    };
    int hit = 0;
    for (const char* s : susp) {
        if (hasAscii(data, s)) {
            r.reasons.push_back(std::string("可疑 API: ") + s);
            hit++;
        }
    }
    r.score += hit * 2;
}

inline void HeuristicEngine::checkPacked(const std::vector<uint8_t>& data, HeuristicResult& r) {
    // 检查 PE 节区熵：打包/加壳的程序节区熵通常 > 7.0
    // 简化：检查文件前 4KB 的高熵（如果几乎全是随机字节，可疑）
    size_t n = data.size() > 4096 ? 4096 : data.size();
    if (n < 128) return;
    double e = entropy(data.data(), n);
    if (e > 7.5) {
        r.reasons.push_back("文件内容高熵（疑似加壳/混淆）");
        r.score += 2;
    }
}

inline void HeuristicEngine::analyzePe(const std::vector<uint8_t>& data, HeuristicResult& r) {
    // 解析 PE：检查入口点位置、节区可疑性（简化版）
    if (data.size() < 0x40) return;
    if (data[0] != 'M' || data[1] != 'Z') return;
    uint32_t peOff = (uint32_t)data[0x3C] | ((uint32_t)data[0x3D] << 8) |
                     ((uint32_t)data[0x3E] << 16) | ((uint32_t)data[0x3F] << 24);
    if (peOff + 24 > data.size()) return;
    if (data[peOff] != 'P' || data[peOff+1] != 'E') return;
    // 节区数量
    uint16_t numSections = (uint16_t)(data[peOff+6] | (data[peOff+7] << 8));
    // 可选头大小
    uint16_t optSize = (uint16_t)(data[peOff+20] | (data[peOff+21] << 8));
    size_t sectionTable = peOff + 24 + optSize;
    if (sectionTable + numSections * 40 > data.size()) return;
    // 检查节区名是否可疑（.upx, .packed, .adata 等）
    for (int i = 0; i < numSections; ++i) {
        size_t off = sectionTable + (size_t)i * 40;
        char name[9] = {0};
        for (int j = 0; j < 8; ++j) name[j] = (char)data[off + j];
        std::string s(name);
        if (s.find("upx") != std::string::npos || s.find("pack") != std::string::npos ||
            s.find("UPX") != std::string::npos || s.find("aspack") != std::string::npos) {
            r.reasons.push_back("可疑节区名: " + s);
            r.score += 3;
        }
    }
}

inline HeuristicResult HeuristicEngine::analyze(const std::string& path, const std::vector<uint8_t>& data) {
    HeuristicResult r;
    analyzePe(data, r);
    checkSuspiciousStrings(data, r);
    checkPacked(data, r);
    if (r.score >= 5) r.level = HeuristicLevel::Malicious;
    else if (r.score >= 2) r.level = HeuristicLevel::Suspicious;
    else r.level = HeuristicLevel::Clean;
    return r;
}

} // namespace av
