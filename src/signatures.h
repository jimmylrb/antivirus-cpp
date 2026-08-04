// signatures.h — ClamAV 病毒库解析与特征条目
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iostream>

namespace av {

// ClamAV HDB 特征：MD5:文件大小:病毒名（哈希精确匹配）
struct HashSignature {
    std::string md5;       // 文件 MD5（32 位十六进制）
    uint64_t    fileSize;  // 文件大小（0 表示任意）
    std::string name;      // 病毒名称
};

// ClamAV NDB 特征：病毒名:目标类型:偏移:十六进制签名
struct HexSignature {
    std::string name;       // 病毒名称
    int         targetType; // 0=任意, 1=PE, 2=ELF, 3=Mach-O
    std::string offset;     // 偏移（* 表示任意位置）
    std::vector<uint8_t> pattern; // 十六进制签名（可含 ?? 通配）
    std::vector<bool>    mask;    // true=该字节参与匹配
};

class SignatureDB {
public:
    // 加载一个 .hdb / .ndb 文本特征文件
    bool loadFromFile(const std::string& path);

    // 解析一行 HDB（MD5:size:name）
    bool parseHdbLine(const std::string& line);
    // 解析一行 NDB（name:target:offset:hexsig）
    bool parseNdbLine(const std::string& line);

    const std::vector<HashSignature>& hashSigs() const { return hashSigs_; }
    const std::vector<HexSignature>&  hexSigs()  const { return hexSigs_; }

    size_t hashCount() const { return hashSigs_.size(); }
    size_t hexCount()  const { return hexSigs_.size(); }
    size_t totalCount() const { return hashSigs_.size() + hexSigs_.size(); }

    void clear() { hashSigs_.clear(); hexSigs_.clear(); }

private:
    // 十六进制字符串转字节数组（支持 ?? 通配）
    static bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out, std::vector<bool>& mask);
    std::vector<HashSignature> hashSigs_;
    std::vector<HexSignature>  hexSigs_;
};

// 十六进制字符 -> 数值
inline int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool SignatureDB::hexToBytes(const std::string& hex,
                                    std::vector<uint8_t>& out,
                                    std::vector<bool>& mask) {
    out.clear(); mask.clear();
    // 去掉空格
    std::string h;
    for (char c : hex) if (c != ' ' && c != '\t' && c != '\r') h += c;
    if (h.empty()) return false;
    for (size_t i = 0; i < h.size();) {
        // ClamAV 高级语法: {n} 精确跳过 n 字节, {-n} 变长跳过(最多n字节) -> 展开为通配
        if (h[i] == '{') {
            size_t close = h.find('}', i);
            if (close == std::string::npos) { out.clear(); mask.clear(); return false; }
            std::string num = h.substr(i + 1, close - i - 1);
            if (!num.empty() && num[0] == '-') num = num.substr(1);
            int n = 0;
            for (char c : num) if (c >= '0' && c <= '9') n = n * 10 + (c - '0');
            if (n <= 0) n = 1;
            if (n > 1024) n = 1024;  // 防御
            for (int k = 0; k < n; ++k) { out.push_back(0); mask.push_back(false); }
            i = close + 1;
            continue;
        }
        // 通配 ? 或 *（ClamAV 中 * 表示 0~N 个字节，这里按单个通配处理）
        if (h[i] == '?' || h[i] == '*') {
            out.push_back(0);
            mask.push_back(false);
            i++;
            continue;
        }
        int hi = hexVal(h[i]);
        int lo = (i + 1 < h.size()) ? hexVal(h[i + 1]) : 0;
        if (hi < 0 || lo < 0) { out.clear(); mask.clear(); return false; }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        mask.push_back(true);
        i += 2;
    }
    return !out.empty();
}

inline bool SignatureDB::parseHdbLine(const std::string& line) {
    // 格式: MD5:文件大小:病毒名
    std::istringstream ss(line);
    std::string md5, sizeStr, name;
    if (!std::getline(ss, md5, ':')) return false;
    if (!std::getline(ss, sizeStr, ':')) return false;
    std::getline(ss, name);
    if (md5.size() != 32 || name.empty()) return false;
    // 只保留合法的十六进制
    for (char c : md5) if (hexVal(c) < 0) return false;
    HashSignature sig;
    sig.md5 = md5;
    sig.fileSize = (sizeStr.empty() || sizeStr == "*") ? 0 : std::stoull(sizeStr);
    sig.name = name;
    hashSigs_.push_back(sig);
    return true;
}

inline bool SignatureDB::parseNdbLine(const std::string& line) {
    // 格式: 病毒名:目标类型:偏移:十六进制签名
    // 可能还有第 5 个字段（文件大小限制），忽略
    std::istringstream ss(line);
    std::string name, targetStr, offset, hex;
    if (!std::getline(ss, name, ':')) return false;
    if (!std::getline(ss, targetStr, ':')) return false;
    if (!std::getline(ss, offset, ':')) return false;
    if (!std::getline(ss, hex, ':')) return false;
    if (name.empty() || hex.empty()) return false;

    HexSignature sig;
    sig.name = name;
    sig.targetType = std::stoi(targetStr);
    sig.offset = offset;
    if (!hexToBytes(hex, sig.pattern, sig.mask)) return false;
    hexSigs_.push_back(sig);
    return true;
}

inline bool SignatureDB::loadFromFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[签名库] 无法打开: " << path << std::endl;
        return false;
    }
    std::string line;
    int hdb = 0, ndb = 0, skip = 0;
    while (std::getline(f, line)) {
        // 跳过空行和注释
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '/' && line.size() > 1 && line[1] == '/') continue;
        // 按字段数量判断 HDB 还是 NDB
        int cols = 0;
        for (char c : line) if (c == ':') cols++;
        if (cols == 2) {           // MD5:size:name
            if (parseHdbLine(line)) hdb++;
        } else if (cols >= 3) {    // name:target:offset:hex[:...]
            if (parseNdbLine(line)) ndb++;
        } else {
            skip++;
        }
    }
    std::cout << "[签名库] " << path << " 加载完成: HDB=" << hdb
              << " NDB=" << ndb << " 跳过=" << skip << std::endl;
    return (hdb + ndb) > 0;
}

} // namespace av
