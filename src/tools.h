// tools.h — 杀毒软件工具箱：全盘扫描 / 垃圾清理 / 启动项管理 / 网络检测 / 文件粉碎 / 软件列表
#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <cstdio>
#include <windows.h>
#include <shlobj.h>
#include <winreg.h>

namespace av {

namespace fs = std::filesystem;

// 宽字符 → ANSI(GBK)
inline std::string toNarrow(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, 0);
    if (n > 0) WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

// ANSI(GBK) → 宽字符
inline std::wstring aToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(n, 0);
    if (n > 0) MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ============ 1. 全盘扫描：枚举所有逻辑盘符 ============
inline std::vector<std::wstring> allDrivePaths() {
    std::vector<std::wstring> out;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (mask & (1 << i)) {
            wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
            UINT type = GetDriveTypeW(root);
            // 固定盘 + 可移动盘（跳过光驱/网络盘，避免卡住）
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE)
                out.push_back(root);
        }
    }
    return out;
}

// ============ 2. 垃圾清理 ============
struct JunkItem {
    std::wstring path;
    std::wstring category;  // 分类：临时文件/回收站/浏览器缓存/日志
    uint64_t size = 0;      // 0=未知
};

inline void collectJunkFiles(std::vector<JunkItem>& items, bool quick = true) {
    // 用户临时目录
    wchar_t tmp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tmp) > 0) {
        std::error_code ec;
        for (auto& e : fs::directory_iterator(tmp, ec)) {
            if (ec) break;
            JunkItem it;
            it.path = e.path().wstring();
            it.category = L"临时文件";
            items.push_back(it);
        }
    }
    // 各浏览器缓存目录（按已知路径）
    struct { const wchar_t* env; const wchar_t* sub; const wchar_t* cat; } dirs[] = {
        { L"LOCALAPPDATA", L"\\Google\\Chrome\\User Data\\Default\\Cache", L"Chrome缓存" },
        { L"LOCALAPPDATA", L"\\Google\\Chrome\\User Data\\Default\\Code Cache", L"Chrome缓存" },
        { L"LOCALAPPDATA", L"\\Microsoft\\Edge\\User Data\\Default\\Cache", L"Edge缓存" },
        { L"APPDATA",      L"\\Mozilla\\Firefox\\Profiles", L"Firefox缓存" },
    };
    for (auto& d : dirs) {
        wchar_t base[MAX_PATH];
        if (GetEnvironmentVariableW(d.env, base, MAX_PATH) > 0) {
            std::wstring p = std::wstring(base) + d.sub;
            std::error_code ec;
            if (fs::exists(p, ec)) {
                JunkItem it;
                it.path = p;
                it.category = d.cat;
                items.push_back(it);
            }
        }
    }
    // Windows 临时/预取/更新缓存
    wchar_t winDir[MAX_PATH];
    if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
        std::wstring win(winDir);
        const wchar_t* subs[] = { L"\\Temp", L"\\Prefetch", L"\\SoftwareDistribution\\Download" };
        for (auto* s : subs) {
            std::wstring p = win + s;
            std::error_code ec;
            if (fs::exists(p, ec)) {
                JunkItem it;
                it.path = p;
                it.category = L"系统缓存";
                items.push_back(it);
            }
        }
    }
    // 回收站（列出根目录）
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (mask & (1 << i)) {
            wchar_t root[4] = { (wchar_t)(L'A' + i), L':', L'\\', 0 };
            UINT type = GetDriveTypeW(root);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                std::wstring rb = std::wstring(root) + L"$Recycle.Bin";
                std::error_code ec;
                if (fs::exists(rb, ec)) {
                    JunkItem it;
                    it.path = rb;
                    it.category = L"回收站";
                    items.push_back(it);
                }
            }
        }
    }
}

// 清空回收站（SHFileOperation）
inline bool emptyRecycleBin() {
    SHFILEOPSTRUCTW op = {0};
    op.wFunc = FO_DELETE;
    op.pFrom = L"";
    // 特殊：空回收站用标志
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    // pFrom 设为特殊路径（不删除任何文件，只清空回收站）
    static wchar_t rec[] = L"\0";
    op.pFrom = rec;
    int r = SHFileOperationW(&op);
    return r == 0;
}

// 删除单个垃圾项（目录递归删除 / 文件删除）
inline bool deleteJunkPath(const std::wstring& path) {
    std::error_code ec;
    if (fs::is_directory(path, ec)) {
        fs::remove_all(path, ec);
    } else {
        fs::remove(path, ec);
    }
    return !ec;
}

// ============ 3. 启动项管理 ============
struct StartupItem {
    std::wstring name;
    std::wstring command;
    std::wstring location;   // HKCU-Run / HKLM-Run / StartupFolder
    HKEY root = NULL;
    std::wstring subKey;
};

inline void collectStartupItems(std::vector<StartupItem>& items) {
    struct { HKEY root; const wchar_t* sub; const wchar_t* loc; } keys[] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU 启动项" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU 启动项" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM 启动项" },
        { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM 启动项" },
    };
    for (auto& k : keys) {
        HKEY key;
        if (RegOpenKeyExW(k.root, k.sub, 0, KEY_READ, &key) == ERROR_SUCCESS) {
            wchar_t name[256], data[MAX_PATH * 2];
            DWORD nIdx = 0;
            while (true) {
                DWORD nName = 256, nData = MAX_PATH * 2, type = 0;
                LONG r = RegEnumValueW(key, nIdx++, name, &nName, NULL, &type,
                                       (BYTE*)data, &nData);
                if (r != ERROR_SUCCESS) break;
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    StartupItem it;
                    it.name = name;
                    it.command = data;
                    it.location = k.loc;
                    it.root = k.root;
                    it.subKey = k.sub;
                    items.push_back(it);
                }
            }
            RegCloseKey(key);
        }
    }
    // 启动文件夹
    wchar_t startup[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, startup) == S_OK) {
        std::error_code ec;
        for (auto& e : fs::directory_iterator(startup, ec)) {
            if (ec) break;
            StartupItem it;
            it.name = e.path().filename().wstring();
            it.command = e.path().wstring();
            it.location = L"启动文件夹";
            items.push_back(it);
        }
    }
}

inline bool removeStartupItem(const StartupItem& it) {
    if (!it.root) return false;
    HKEY key;
    if (RegOpenKeyExW(it.root, it.subKey.c_str(), 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    LONG r = RegDeleteValueW(key, it.name.c_str());
    RegCloseKey(key);
    return r == ERROR_SUCCESS;
}

// ============ 4. 网络连接检测（netstat 解析） ============
struct NetConn {
    std::wstring proto;
    std::wstring local;
    std::wstring remote;
    std::wstring state;
    DWORD pid = 0;
    std::wstring procName;
};

inline std::wstring pidToName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    std::wstring name;
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) { name = pe.szExeFile; break; }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    return name;
}

inline std::vector<NetConn> collectNetConnections() {
    std::vector<NetConn> out;
    FILE* p = _wpopen(L"netstat -ano", L"r");
    if (!p) return out;
    char line[1024];
    while (fgets(line, sizeof(line), p)) {
        // TCP 行示例:  TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
        std::string s(line);
        if (s.find("TCP") == std::string::npos && s.find("UDP") == std::string::npos) continue;
        if (s.find("LISTENING") == std::string::npos && s.find("ESTABLISHED") == std::string::npos
            && s.find("TIME_WAIT") == std::string::npos) continue;
        // 简单分词
        std::vector<std::string> tok;
        size_t i = 0;
        while (i < s.size()) {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
            if (i >= s.size()) break;
            size_t j = s.find_first_of(" \t\r\n", i);
            tok.push_back(s.substr(i, j - i));
            i = (j == std::string::npos) ? s.size() : j;
        }
        if (tok.size() < 5) continue;
        NetConn c;
        c.proto = aToW(tok[0]);
        c.local = aToW(tok[1]);
        c.remote = aToW(tok[2]);
        c.state = aToW(tok[3]);
        try { c.pid = (DWORD)std::stoul(tok[4]); } catch (...) { c.pid = 0; }
        if (c.pid == 0) continue;
        c.procName = pidToName(c.pid);
        out.push_back(c);
    }
    _pclose(p);
    return out;
}

// ============ 5. 文件粉碎（覆盖写 + 删除） ============
inline bool shredFile(const std::wstring& path, int passes = 3) {
    std::error_code ec;
    auto sz = fs::file_size(path, ec);
    if (ec) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    for (int pass = 0; pass < passes; ++pass) {
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        DWORD chunk = 4096;
        std::vector<BYTE> buf((size_t)chunk, (BYTE)(pass * 85 + 7));
        uint64_t left = sz;
        while (left > 0) {
            DWORD n = (DWORD)(left < chunk ? left : chunk);
            DWORD written = 0;
            if (!WriteFile(h, buf.data(), n, &written, NULL) || written != n) { ok = false; break; }
            left -= written;
        }
        if (!ok) break;
        FlushFileBuffers(h);
    }
    CloseHandle(h);
    if (ok) fs::remove(path, ec);
    return ok;
}

// ============ 6. 已安装软件列表 ============
struct InstalledApp {
    std::wstring name;
    std::wstring version;
    std::wstring publisher;
    std::wstring installLocation;
};

inline void collectInstalledApps(std::vector<InstalledApp>& apps) {
    struct { HKEY root; const wchar_t* sub; } keys[] = {
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
    };
    for (auto& k : keys) {
        HKEY key;
        if (RegOpenKeyExW(k.root, k.sub, 0, KEY_READ, &key) != ERROR_SUCCESS) continue;
        wchar_t subName[256];
        DWORD nIdx = 0;
        while (true) {
            DWORD nSub = 256;
            LONG r = RegEnumKeyExW(key, nIdx++, subName, &nSub, NULL, NULL, NULL, NULL);
            if (r != ERROR_SUCCESS) break;
            HKEY sub;
            if (RegOpenKeyExW(key, subName, 0, KEY_READ, &sub) != ERROR_SUCCESS) continue;
            wchar_t val[1024];
            DWORD nVal = 1024;
            InstalledApp app;
            if (RegQueryValueExW(sub, L"DisplayName", NULL, NULL, (BYTE*)val, &nVal) == ERROR_SUCCESS)
                app.name = val;
            nVal = 1024;
            if (RegQueryValueExW(sub, L"DisplayVersion", NULL, NULL, (BYTE*)val, &nVal) == ERROR_SUCCESS)
                app.version = val;
            nVal = 1024;
            if (RegQueryValueExW(sub, L"Publisher", NULL, NULL, (BYTE*)val, &nVal) == ERROR_SUCCESS)
                app.publisher = val;
            nVal = 1024;
            if (RegQueryValueExW(sub, L"InstallLocation", NULL, NULL, (BYTE*)val, &nVal) == ERROR_SUCCESS)
                app.installLocation = val;
            RegCloseKey(sub);
            if (!app.name.empty())
                apps.push_back(app);
        }
        RegCloseKey(key);
    }
}

} // namespace av
