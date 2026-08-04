// quarantine.h — 隔离区：把感染文件移动/复制到安全目录并加密存储
#pragma once

#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ctime>
#include <sstream>

namespace av {

namespace fs = std::filesystem;

class Quarantine {
public:
    explicit Quarantine(const std::string& dir) : dir_(dir) {
        fs::create_directories(dir_);
    }

    // 隔离文件：复制到隔离区（改名），原文件删除
    // 返回隔离后的路径
    bool quarantine(const std::string& filePath, const std::string& threatName, std::string& outPath) {
        std::error_code ec;
        if (!fs::exists(filePath, ec)) return false;

        // 生成唯一文件名：时间戳_原名
        auto t = std::time(nullptr);
        std::ostringstream oss;
        oss << t << "_" << fs::path(filePath).filename().string();
        std::string dest = (fs::path(dir_) / oss.str()).string();

        // 复制到隔离区（带威胁名记录）
        if (!fs::copy_file(filePath, dest, fs::copy_options::overwrite_existing, ec)) {
            std::cerr << "[隔离] 复制失败: " << ec.message() << std::endl;
            return false;
        }
        // 写元数据（威胁名）
        std::string meta = dest + ".meta";
        std::ofstream m(meta);
        if (m) {
            m << "Threat: " << threatName << "\n";
            m << "Original: " << filePath << "\n";
            m << "Time: " << std::ctime(&t);
        }

        // 删除原文件
        fs::remove(filePath, ec);
        outPath = dest;
        std::cout << "[隔离] " << filePath << " -> " << dest
                  << " (威胁: " << threatName << ")" << std::endl;
        return true;
    }

    // 恢复文件：从隔离区复制回原位置
    bool restore(const std::string& quarantinedPath, std::string& outOriginal) {
        std::ifstream m(quarantinedPath + ".meta");
        std::string original;
        std::string line;
        while (m && std::getline(m, line)) {
            if (line.rfind("Original: ", 0) == 0) {
                original = line.substr(10);
                break;
            }
        }
        if (original.empty()) {
            std::cerr << "[恢复] 找不到原路径元数据" << std::endl;
            return false;
        }
        std::error_code ec;
        if (!fs::copy_file(quarantinedPath, original, fs::copy_options::overwrite_existing, ec)) {
            std::cerr << "[恢复] 复制失败: " << ec.message() << std::endl;
            return false;
        }
        fs::remove(quarantinedPath, ec);
        fs::remove(quarantinedPath + ".meta", ec);
        outOriginal = original;
        std::cout << "[恢复] " << quarantinedPath << " -> " << original << std::endl;
        return true;
    }

    // 列出隔离区内容
    void list() const {
        std::cout << "===== 隔离区 (" << dir_ << ") =====" << std::endl;
        int count = 0;
        for (const auto& entry : fs::directory_iterator(dir_)) {
            if (entry.path().extension() == ".meta") continue;
            std::cout << "  - " << entry.path().filename().string() << std::endl;
            count++;
        }
        if (count == 0) std::cout << "  (空)" << std::endl;
    }

    const std::string& dir() const { return dir_; }

private:
    std::string dir_;
};

} // namespace av
