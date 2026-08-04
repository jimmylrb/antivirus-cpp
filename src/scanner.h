// scanner.h — 扫描引擎：目录遍历 + 文件扫描 + 匹配（支持白名单 + 多线程）
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>
#include "signatures.h"
#include "md5.h"
#include "whitelist.h"

namespace av {

namespace fs = std::filesystem;

// 单个文件的扫描结果
struct ScanResult {
    std::string path;
    std::string threat;      // 空 = 干净
    bool        infected = false;
};

// 扫描统计（线程安全）
struct ScanStats {
    std::atomic<size_t> filesScanned{0};
    std::atomic<size_t> filesInfected{0};
    std::atomic<size_t> errors{0};
    std::atomic<size_t> bytesRead{0};
};

class Scanner {
public:
    Scanner(const SignatureDB& db) : db_(db) {}

    void setWhitelist(Whitelist* wl) { whitelist_ = wl; }

    // 扫描一个文件，返回是否感染
    bool scanFile(const fs::path& path, ScanResult& out);

    // 单线程递归扫描目录
    void scanDirectory(const fs::path& root, std::vector<ScanResult>& results,
                       std::function<void(const ScanResult&)> cb = nullptr);

    // 多线程并行扫描目录（推荐，速度快 4-8 倍）
    void scanDirectoryParallel(const fs::path& root, std::vector<ScanResult>& results,
                               size_t numThreads = 0,
                               std::function<void(const ScanResult&)> cb = nullptr);

    // 收集目录下所有文件
    static void collectFiles(const fs::path& root, std::vector<fs::path>& out);

    const ScanStats& stats() const { return stats_; }
    void resetStats() {
        stats_.filesScanned = 0;
        stats_.filesInfected = 0;
        stats_.errors = 0;
        stats_.bytesRead = 0;
    }

    static std::string fileMd5(const fs::path& path) { return md5::hashFile(path.string()); }

    static size_t defaultThreadCount() {
        unsigned hw = std::thread::hardware_concurrency();
        return hw > 0 ? (hw > 16 ? 16 : hw) : 4;
    }

private:
    const SignatureDB& db_;
    Whitelist* whitelist_ = nullptr;
    ScanStats stats_;

    bool findPattern(const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& pattern,
                     const std::vector<bool>& mask);
};

// ============== 实现 ==============

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

    // 计算 MD5（HDB 匹配 + 白名单检查都需要）
    std::string hash;
    auto getHash = [&]() -> const std::string& {
        if (hash.empty()) hash = fileMd5(path);
        return hash;
    };

    // 白名单检查：信任文件直接跳过
    if (whitelist_ && whitelist_->contains(getHash())) {
        return false;
    }

    // 1) HDB 哈希匹配
    for (const auto& hs : db_.hashSigs()) {
        if (hs.fileSize != 0 && hs.fileSize != size) continue;
        if (getHash() == hs.md5) {
            out.infected = true;
            out.threat = hs.name;
            stats_.filesInfected++;
            return true;
        }
    }

    // 2) NDB 十六进制特征匹配（读取前 1MB）
    std::vector<uint8_t> data;
    const size_t MAX_READ = 1024 * 1024;
    std::ifstream f(path, std::ios::binary);
    if (f) {
        data.resize(std::min<size_t>((size_t)size, MAX_READ));
        f.read(reinterpret_cast<char*>(data.data()), data.size());
        size_t got = (size_t)f.gcount();
        data.resize(got);
        stats_.bytesRead += got;
    }

    int fileType = 0;
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') fileType = 1;
    else if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') fileType = 2;

    for (const auto& ns : db_.hexSigs()) {
        if (ns.targetType != 0 && ns.targetType != fileType) continue;
        if (findPattern(data, ns.pattern, ns.mask)) {
            out.infected = true;
            out.threat = ns.name;
            stats_.filesInfected++;
            return true;
        }
    }
    return false;
}

inline void Scanner::collectFiles(const fs::path& root, std::vector<fs::path>& out) {
    std::error_code ec;
    if (!fs::exists(root, ec)) return;
    if (fs::is_regular_file(root, ec)) { out.push_back(root); return; }
    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (it->is_regular_file(ec)) out.push_back(it->path());
    }
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

inline void Scanner::scanDirectoryParallel(const fs::path& root,
                                           std::vector<ScanResult>& results,
                                           size_t numThreads,
                                           std::function<void(const ScanResult&)> cb) {
    // 收集文件列表
    std::vector<fs::path> files;
    collectFiles(root, files);
    if (files.empty()) return;

    if (numThreads == 0) numThreads = defaultThreadCount();
    if (numThreads > files.size()) numThreads = files.size();

    // 线程池：原子索引分配任务
    std::atomic<size_t> next{0};
    std::mutex resultsMutex;
    results.clear();

    auto worker = [&]() {
        while (true) {
            size_t i = next.fetch_add(1);
            if (i >= files.size()) break;
            ScanResult r;
            scanFile(files[i], r);
            {
                std::lock_guard<std::mutex> lk(resultsMutex);
                results.push_back(r);
            }
            if (cb) cb(r);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    for (size_t t = 0; t < numThreads; ++t)
        threads.emplace_back(worker);
    for (auto& t : threads) t.join();
}

} // namespace av
