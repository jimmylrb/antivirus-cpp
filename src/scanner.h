// scanner.h — 扫描引擎：目录遍历 + 文件扫描 + 匹配
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include "signatures.h"
#include "md5.h"

namespace av {

namespace fs = std::filesystem;

// 单个文件的扫描结果
struct ScanResult {
    std::string path;
    std::string threat;      // 空 = 干净
    bool        infected = false;
};

// 扫描统计
struct ScanStats {
    size_t filesScanned = 0;
    size_t filesInfected = 0;
    size_t errors = 0;
    double bytesRead = 0;
};

class Scanner {
public:
    Scanner(const SignatureDB& db) : db_(db) {}

    // 扫描一个文件，返回是否感染（可通过 outResult 取详情）
    bool scanFile(const fs::path& path, ScanResult& out);

    // 递归扫描目录，cb 每扫描一个文件回调（用于进度显示）
    void scanDirectory(const fs::path& root, std::vector<ScanResult>& results,
                       std::function<void(const ScanResult&)> cb = nullptr);

    const ScanStats& stats() const { return stats_; }
    void resetStats() { stats_ = ScanStats(); }

    // 计算文件 MD5
    static std::string fileMd5(const fs::path& path);

private:
    const SignatureDB& db_;
    ScanStats stats_;

    // 在缓冲区中查找十六进制特征（支持通配）
    bool findPattern(const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& pattern,
                     const std::vector<bool>& mask);
};

// ============== 实现 ==============

inline std::string Scanner::fileMd5(const fs::path& path) {
    // 简单 MD5 实现（用于 HDB 匹配）— 用系统 API 或内置算法
    // 这里使用内置的轻量实现（见 md5.h），由 main 提供
    return md5::hashFile(path.string());
}

inline bool Scanner::findPattern(const std::vector<uint8_t>& data,
                                 const std::vector<uint8_t>& pattern,
                                 const std::vector<bool>& mask) {
    if (pattern.empty() || data.size() < pattern.size()) return false;
    for (size_t i = 0; i + pattern.size() <= data.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] && data[i + j] != pattern[j]) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

inline bool Scanner::scanFile(const fs::path& path, ScanResult& out) {
    out.path = path.string();
    out.infected = false;
    out.threat.clear();

    stats_.filesScanned++;
    std::error_code ec;
    auto size = fs::file_size(path, ec);
    if (ec) { stats_.errors++; return false; }
    if (size == 0) return false;

    // 1) HDB 哈希匹配（先试大小过滤）
    std::string hash;
    for (const auto& hs : db_.hashSigs()) {
        if (hs.fileSize != 0 && hs.fileSize != size) continue;
        if (hash.empty()) hash = fileMd5(path);
        if (hash == hs.md5) {
            out.infected = true;
            out.threat = hs.name;
            stats_.filesInfected++;
            return true;
        }
    }

    // 2) NDB 十六进制特征匹配（读取文件内容）
    // 限制读取前 1MB（多数病毒特征在文件头部）
    std::vector<uint8_t> data;
    const size_t MAX_READ = 1024 * 1024;
    std::ifstream f(path, std::ios::binary);
    if (f) {
        data.resize(std::min<size_t>(size, MAX_READ));
        f.read(reinterpret_cast<char*>(data.data()), data.size());
        size_t got = f.gcount();
        data.resize(got);
        stats_.bytesRead += got;
    }

    // 判断文件类型（PE/ELF/Mach-O）
    int fileType = 0;
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') fileType = 1;      // PE
    else if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') fileType = 2; // ELF

    for (const auto& ns : db_.hexSigs()) {
        // 目标类型过滤（0=任意）
        if (ns.targetType != 0 && ns.targetType != fileType) continue;
        if (findPattern(data, ns.pattern, ns.mask)) {
            out.infected = true;
            out.threat = ns.name;
            stats_.filesInfected++;
            return true;
        }
    }

    stats_.filesScanned++;
    return false;
}

inline void Scanner::scanDirectory(const fs::path& root,
                                   std::vector<ScanResult>& results,
                                   std::function<void(const ScanResult&)> cb) {
    std::error_code ec;
    if (!fs::exists(root, ec)) {
        std::cerr << "[扫描] 路径不存在: " << root << std::endl;
        return;
    }
    if (fs::is_regular_file(root, ec)) {
        ScanResult r;
        scanFile(root, r);
        results.push_back(r);
        if (cb) cb(r);
        return;
    }
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (it->is_regular_file(ec)) {
            ScanResult r;
            scanFile(it->path(), r);
            results.push_back(r);
            if (cb) cb(r);
        }
    }
}

} // namespace av
