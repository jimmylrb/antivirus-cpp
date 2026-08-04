// whitelist.h — 白名单/信任列表
// 基于文件 MD5 指纹，白名单内的文件扫描时直接跳过（处理误报）
#pragma once

#include <string>
#include <unordered_set>
#include <fstream>
#include <iostream>
#include <mutex>
#include <filesystem>

namespace av {

namespace fs = std::filesystem;

class Whitelist {
public:
    explicit Whitelist(const std::string& path = "whitelist.txt")
        : path_(path) { load(); }

    // 加载白名单文件（每行一个 MD5）
    void load() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
        std::ifstream f(path_);
        if (!f) return;
        std::string line;
        while (std::getline(f, line)) {
            // 去掉空白和注释
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
                line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            // 只保留 32 位十六进制 MD5
            if (line.size() >= 32) {
                std::string md5 = line.substr(0, 32);
                bool valid = true;
                for (char c : md5) {
                    bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                    if (!ok) { valid = false; break; }
                }
                if (valid) entries_.insert(md5);
            }
        }
        std::cout << "[白名单] 已加载 " << entries_.size() << " 条信任记录" << std::endl;
    }

    void save() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ofstream f(path_);
        if (!f) return;
        for (const auto& md5 : entries_)
            f << md5 << "\n";
    }

    bool contains(const std::string& md5) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.count(md5) > 0;
    }

    void add(const std::string& md5) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            entries_.insert(md5);
        }
        save();
        std::cout << "[白名单] 已信任 " << md5 << std::endl;
    }

    void remove(const std::string& md5) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            entries_.erase(md5);
        }
        save();
        std::cout << "[白名单] 已移除 " << md5 << std::endl;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    void list() const {
        std::lock_guard<std::mutex> lock(mutex_);
        int n = 0;
        for (const auto& md5 : entries_) {
            std::cout << "  " << md5 << std::endl;
            n++;
        }
        if (n == 0) std::cout << "  (空)" << std::endl;
    }

    void list_usage() const {
        std::cout << "用法: blockav whitelist --list | --add <文件> | --remove <MD5>" << std::endl;
    }

    const std::string& path() const { return path_; }

private:
    std::string path_;
    std::unordered_set<std::string> entries_;
    mutable std::mutex mutex_;
};

} // namespace av
