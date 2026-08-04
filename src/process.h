// process.h — 进程/内存扫描：枚举运行进程 + 特征库扫描 + 可疑进程识别
#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <windows.h>
#include <tlhelp32.h>
#include "scanner.h"
#include "md5.h"

namespace av {

struct ProcessResult {
    DWORD   pid = 0;
    std::string name;       // 进程名（exe 文件名）
    std::string path;       // 可执行文件路径（GBK）
    std::string threat;     // 空 = 干净/正常
    bool    infected = false;
    bool    suspicious = false;  // 启发式可疑（非特征库命中）
};

// 枚举所有进程（含可执行路径）
inline std::vector<ProcessResult> enumProcesses() {
    std::vector<ProcessResult> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessResult r;
            r.pid = pe.th32ProcessID;
            int nName = WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, NULL, 0, NULL, NULL);
            r.name.assign(nName > 0 ? nName - 1 : 0, 0);
            if (nName > 1) WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, &r.name[0], nName, NULL, NULL);
            // 获取进程可执行文件完整路径
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                wchar_t buf[MAX_PATH];
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
                    // 转 GBK（与 ScanResult.path 编码一致）
                    int n = WideCharToMultiByte(CP_ACP, 0, buf, (int)sz, NULL, 0, NULL, NULL);
                    r.path.assign(n, 0);
                    WideCharToMultiByte(CP_ACP, 0, buf, (int)sz, &r.path[0], n, NULL, NULL);
                }
                CloseHandle(h);
            }
            out.push_back(r);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// 进程名是否为系统关键进程（降低误报）
inline bool isSystemProcessName(const std::string& name) {
    static const char* sys[] = {
        "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "explorer.exe",
        "dwm.exe", "taskhostw.exe", "SearchIndexer.exe", "RuntimeBroker.exe",
        "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
        "conhost.exe", "fontdrvhost.exe", "dllhost.exe", "sihost.exe",
        "ctfmon.exe", "MsMpEng.exe", "SecurityHealthService.exe", "WerFault.exe",
        "audiodg.exe", "Memory Compression", "Registry", "winlogon.exe"
    };
    for (auto* s : sys) {
        if (_stricmp(name.c_str(), s) == 0) return true;
    }
    return false;
}

// 可疑进程启发式判断（返回原因，空串 = 正常）
inline std::string suspiciousProcessReason(const ProcessResult& r, const std::string& username) {
    if (r.path.empty()) {
        if (isSystemProcessName(r.name)) return "";
        return "无法读取路径（可能被隐藏或权限受限）";
    }
    // 常见恶意落点目录
    std::string low = r.path;
    for (auto& c : low) c = (char)tolower((unsigned char)c);
    auto contains = [&](const char* sub) { return low.find(sub) != std::string::npos; };

    std::vector<std::string> reasons;
    if (contains("\\appdata\\local\\temp\\") || contains("\\windows\\temp\\") || contains("\\temp\\"))
        reasons.push_back("运行在临时目录");
    if (contains("\\recycle.bin\\") || contains("\\$recycle.bin\\"))
        reasons.push_back("运行在回收站");
    if (contains("\\appdata\\local\\microsoft\\windows\\inetcache\\"))
        reasons.push_back("运行在浏览器缓存");
    // 排除常见正常软件目录（避免误报）
    auto isKnownApp = [&]() {
        if (contains("\\google\\") || contains("\\chrome") || contains("\\microsoft\\")
            || contains("\\mozilla\\") || contains("\\firefox\\") || contains("\\tencent\\")
            || contains("\\wechat") || contains("\\qq\\") || contains("\\baidu\\")
            || contains("\\360\\") || contains("\\huorong\\") || contains("\\wps\\")
            || contains("\\nodejs\\") || contains("\\python") || contains("\\java\\")
            || contains("\\clash") || contains("\\v2ray")) return true;
        return false;
    };
    if (contains("\\appdata\\roaming\\") && !isKnownApp())
        reasons.push_back("运行在 Roaming 目录（非常见软件）");
    // 随机/可疑文件名（8 位十六进制等）
    if (r.name.size() == 8 && r.name.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
        reasons.push_back("8位十六进制随机名");
    // 常见恶意进程名特征
    if (contains("crypto") || contains("miner") || contains("coin"))
        reasons.push_back("疑似挖矿相关");
    if (contains("keylog") || contains("stealer") || contains("rat.exe") || contains("backdoor"))
        reasons.push_back("疑似远控/窃密");
    if (contains("\\desktop\\"))
        reasons.push_back("运行在桌面目录");

    std::string joined;
    for (size_t i = 0; i < reasons.size() && i < 2; ++i) {
        if (!joined.empty()) joined += " | ";
        joined += reasons[i];
    }
    return joined;
}

// 全进程扫描：HDB 哈希匹配 + 可疑启发式（不跑 NDB 全量，避免对每个 exe 慢匹配）
inline void scanProcesses(const SignatureDB& db, std::vector<ProcessResult>& results,
                          bool useHeuristic = true) {
    results.clear();
    // 排除自身进程
    std::string selfPath;
    {
        wchar_t buf[MAX_PATH];
        DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
        if (n > 0) {
            int sz = WideCharToMultiByte(CP_ACP, 0, buf, (int)n, NULL, 0, NULL, NULL);
            selfPath.assign(sz > 0 ? sz : 0, 0);
            if (sz > 0) WideCharToMultiByte(CP_ACP, 0, buf, (int)n, &selfPath[0], sz, NULL, NULL);
        }
    }
    auto procs = enumProcesses();
    std::error_code ec;
    for (auto& r : procs) {
        if (r.path.empty()) continue;
        if (!selfPath.empty() && _stricmp(r.path.c_str(), selfPath.c_str()) == 0) continue;
        // 1) HDB 哈希匹配（快）
        {
            auto size = std::filesystem::file_size(r.path, ec);
            if (!ec && size > 0) {
                std::string md5 = Scanner::fileMd5(r.path);
                for (const auto& hs : db.hashSigs()) {
                    if (hs.fileSize != 0 && hs.fileSize != (uint64_t)size) continue;
                    if (md5 == hs.md5) {
                        r.infected = true;
                        r.threat = hs.name;
                        break;
                    }
                }
            }
        }
        if (r.infected) { results.push_back(r); continue; }
        // 2) 可疑启发式
        if (useHeuristic && !isSystemProcessName(r.name)) {
            std::string why = suspiciousProcessReason(r, "");
            if (!why.empty()) {
                r.suspicious = true;
                r.threat = "[可疑] " + why;
                results.push_back(r);
            }
        }
    }
}

// 结束进程（需管理员权限）
inline bool killProcess(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok;
}

} // namespace av
