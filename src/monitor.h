// monitor.h — 实时文件监控（ReadDirectoryChangesW）
// 监视目录变化，新文件出现时自动扫描
#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <iostream>
#include <windows.h>

#include "scanner.h"

namespace av {

class FileMonitor {
public:
    // dir: 监控目录; scanner: 扫描引擎; onThreat: 发现威胁时的回调
    FileMonitor(const std::string& dir, Scanner& scanner,
                std::function<void(const std::string&, const std::string&)> onThreat = nullptr)
        : dir_(dir), scanner_(scanner), onThreat_(onThreat) {}

    ~FileMonitor() { stop(); }

    // 启动监控（后台线程）
    bool start() {
        if (running_) return true;
        dirHandle_ = CreateFileA(
            dir_.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,  // 同步模式（配合同步 ReadDirectoryChangesW）
            NULL);
        if (dirHandle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[监控] 无法打开目录: " << dir_ << " (错误 "
                      << GetLastError() << ")" << std::endl;
            return false;
        }
        running_ = true;
        thread_ = std::thread(&FileMonitor::watchLoop, this);
        return true;
    }

    void stop() {
        if (!running_) return;
        running_ = false;
        if (dirHandle_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(dirHandle_, NULL);
            CloseHandle(dirHandle_);
            dirHandle_ = INVALID_HANDLE_VALUE;
        }
        if (thread_.joinable()) thread_.join();
    }

    bool running() const { return running_; }

private:
    void watchLoop() {
        char buffer[65536];
        std::cout << "[监控] 开始监视: " << dir_ << std::endl;
        while (running_) {
            DWORD bytesReturned = 0;
            // 同步版本：阻塞等待目录变化通知
            BOOL ok = ReadDirectoryChangesW(
                dirHandle_, buffer, sizeof(buffer), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned, NULL, NULL);
            if (!ok) {
                DWORD err = GetLastError();
                if (!running_) break;
                std::cerr << "[监控] ReadDirectoryChangesW 失败 (错误 " << err << ")" << std::endl;
                Sleep(1000);
                continue;
            }
            // 处理通知
            FILE_NOTIFY_INFORMATION* info = (FILE_NOTIFY_INFORMATION*)buffer;
            while (true) {
                handleNotify(info);
                if (info->NextEntryOffset == 0) break;
                info = (FILE_NOTIFY_INFORMATION*)((BYTE*)info + info->NextEntryOffset);
            }
        }
        std::cout << "[监控] 已停止" << std::endl;
    }

    void handleNotify(FILE_NOTIFY_INFORMATION* info) {
        // 只关心新增/修改/重命名
        if (info->Action == FILE_ACTION_REMOVED) return;
        // 文件名（UTF-16 -> UTF-8）
        std::wstring wname(info->FileName, info->FileNameLength / 2);
        std::string name = utf16ToUtf8(wname);
        std::string full = dir_ + "\\" + name;
        std::cerr << "[监控][调试] 收到通知: action=" << info->Action
                  << " name=" << name << std::endl;

        // 跳过目录（简单判断：有扩展名才扫）
        if (full.find('.') == std::string::npos) return;

        ScanResult result;
        if (scanner_.scanFile(full, result) && result.infected) {
            std::cerr << "[监控][威胁] " << full << " -> " << result.threat << std::endl;
            if (onThreat_) onThreat_(full, result.threat);
        }
    }

    static std::string utf16ToUtf8(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        std::string out(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &out[0], size, NULL, NULL);
        return out;
    }

    std::string dir_;
    Scanner& scanner_;
    std::function<void(const std::string&, const std::string&)> onThreat_;
    HANDLE dirHandle_ = INVALID_HANDLE_VALUE;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace av
