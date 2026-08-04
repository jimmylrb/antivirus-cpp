// yara.h — 简化版 YARA 规则引擎
// 支持 YARA 常用子集：
//   rule Name {
//     strings:
//       $a = "text string"
//       $b = { 6A 40 68 00 30 00 00 6A 14 8B EC 83 EC 28 53 56 57 }
//       $c = { 4D 5A ?? 00 }
//     condition:
//       any of them / all of them / $a / $a and $b / 2 of them
//   }
#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cctype>

namespace av {

// 单条字符串规则
struct YaraString {
    std::string id;                       // $a
    std::vector<uint8_t> bytes;           // 匹配字节
    std::vector<bool> mask;               // true=参与匹配
    bool found = false;                   // 匹配结果
};

// 条件表达式（简化）
struct YaraCondition {
    enum Type { ANY_OF, ALL_OF, COUNT_OF, SINGLE, AND, NONE } type = NONE;
    size_t count = 0;                     // COUNT_OF 的数量
    std::vector<std::string> ids;         // 涉及的 $id
    YaraCondition* left = nullptr;        // AND 左
    YaraCondition* right = nullptr;       // AND 右
    ~YaraCondition() { delete left; delete right; }
};

struct YaraRule {
    std::string name;
    std::vector<YaraString> strings;
    YaraCondition condition;
    std::vector<std::string> tags;
    bool matched = false;
};

class YaraEngine {
public:
    // 从文件加载规则
    bool loadFromFile(const std::string& path);

    // 扫描数据，返回匹配的规则
    std::vector<std::string> scan(const std::vector<uint8_t>& data);

    const std::vector<YaraRule>& rules() const { return rules_; }
    size_t count() const { return rules_.size(); }

private:
    std::vector<YaraRule> rules_;

    bool parseRule(const std::string& text, size_t& pos, YaraRule& rule);
    bool parseStrings(const std::string& text, size_t& pos, YaraRule& rule);
    bool parseCondition(const std::string& text, size_t& pos, YaraRule& rule);
    YaraCondition* parseConditionExpr(const std::string& text, size_t& pos);
    bool evalCondition(const YaraCondition& cond, const std::vector<YaraString>& strs);
    void matchString(const std::vector<uint8_t>& data, YaraString& s);

    static void skipWs(const std::string& t, size_t& p) {
        while (p < t.size() && (t[p] == ' ' || t[p] == '\t' || t[p] == '\n' || t[p] == '\r')) p++;
    }
};

inline bool YaraEngine::loadFromFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) { std::cerr << "[YARA] 无法打开规则文件: " << path << std::endl; return false; }
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    rules_.clear();
    size_t pos = 0;
    int parsed = 0;
    while (pos < text.size()) {
        skipWs(text, pos);
        // 找 "rule" 关键字
        size_t r = text.find("rule", pos);
        if (r == std::string::npos) break;
        pos = r;
        YaraRule rule;
        if (parseRule(text, pos, rule)) { rules_.push_back(rule); parsed++; }
    }
    std::cout << "[YARA] 加载 " << parsed << " 条规则 (来自 " << path << ")" << std::endl;
    return parsed > 0;
}

inline bool YaraEngine::parseRule(const std::string& t, size_t& p, YaraRule& rule) {
    p += 4;  // skip "rule"
    skipWs(t, p);
    // 规则名
    size_t start = p;
    while (p < t.size() && (isalnum((unsigned char)t[p]) || t[p] == '_')) p++;
    rule.name = t.substr(start, p - start);
    skipWs(t, p);
    // tags（可选，: tag1 tag2）
    if (p < t.size() && t[p] == ':') {
        p++;
        while (p < t.size() && t[p] != '{') {
            if (isalnum((unsigned char)t[p]) || t[p] == '_') {
                size_t s = p;
                while (p < t.size() && (isalnum((unsigned char)t[p]) || t[p] == '_')) p++;
                rule.tags.push_back(t.substr(s, p - s));
            } else p++;
        }
    }
    skipWs(t, p);
    if (p >= t.size() || t[p] != '{') return false;
    p++;  // skip {
    // 找匹配的 }（深度计数，正确处理 hex 字符串里的 { }）
    size_t braceEnd = p;
    int depth = 1;
    while (braceEnd < t.size() && depth > 0) {
        if (t[braceEnd] == '{') depth++;
        else if (t[braceEnd] == '}') depth--;
        if (depth > 0) braceEnd++;
    }
    if (depth != 0) return false;
    std::string body = t.substr(p, braceEnd - p);
    p = braceEnd + 1;

    // 解析 body
    size_t bp = 0;
    // strings 部分
    size_t si = body.find("strings:");
    if (si != std::string::npos) {
        bp = si + 8;
        // 收集字符串直到 condition:
        size_t ci = body.find("condition:", si);
        std::string strSection = (ci != std::string::npos) ? body.substr(bp, ci - bp) : body.substr(bp);
        std::istringstream ss(strSection);
        std::string line;
        while (std::getline(ss, line)) {
            // 格式: $id = "text" 或 $id = { hex }
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string idpart = line.substr(0, eq);
            size_t d = idpart.find('$');
            if (d == std::string::npos) continue;
            std::string id;
            for (size_t i = d + 1; i < idpart.size(); ++i) {
                if (isalnum((unsigned char)idpart[i]) || idpart[i] == '_') id += idpart[i];
                else break;
            }
            std::string val = line.substr(eq + 1);
            // 去掉注释（仅当不影响字符串引号对时；URL 里的 // 不能被误伤）
            YaraString ys;
            ys.id = id;
            size_t q1 = val.find('"');
            size_t b1 = val.find('{');
            if (q1 != std::string::npos) {
                // 文本字符串：直接找完整引号对
                size_t q2 = val.find('"', q1 + 1);
                if (q2 == std::string::npos) continue;
                std::string str = val.substr(q1 + 1, q2 - q1 - 1);
                for (char ch : str) { ys.bytes.push_back((uint8_t)ch); ys.mask.push_back(true); }
            } else if (b1 != std::string::npos) {
                // 十六进制字符串：去掉行尾注释再解析
                size_t c = val.find("//");
                if (c != std::string::npos) val = val.substr(0, c);
                size_t b2 = val.find('}', b1 + 1);
                if (b2 == std::string::npos) continue;
                std::string hex = val.substr(b1 + 1, b2 - b1 - 1);
                std::string h;
                for (char ch : hex) if (!isspace((unsigned char)ch)) h += ch;
                for (size_t i = 0; i < h.size();) {
                    if (h[i] == '?') {
                        if (i + 1 < h.size() && h[i+1] == '?') { ys.bytes.push_back(0); ys.mask.push_back(false); i += 2; }
                        else { ys.bytes.push_back(0); ys.mask.push_back(false); i++; }
                    } else if (isxdigit((unsigned char)h[i]) && i + 1 < h.size() && isxdigit((unsigned char)h[i+1])) {
                        auto hv = [](char ch2) { return isdigit((unsigned char)ch2) ? ch2 - '0' : (tolower((unsigned char)ch2) - 'a' + 10); };
                        ys.bytes.push_back((uint8_t)((hv(h[i]) << 4) | hv(h[i+1])));
                        ys.mask.push_back(true);
                        i += 2;
                    } else i++;
                }
            } else continue;
            if (!ys.bytes.empty()) rule.strings.push_back(ys);
        }
    }
    // condition 部分
    size_t ci = body.find("condition:");
    if (ci != std::string::npos) {
        bp = ci + 10;
        // 去掉末尾 }
        std::string condStr = body.substr(bp);
        size_t end = condStr.find('}');
        if (end != std::string::npos) condStr = condStr.substr(0, end);
        // 简化：只识别 "any of them" / "all of them" / "N of them" / "$id" / "$id and $id"
        std::string c = condStr;
        size_t andp = c.find(" and ");
        if (andp != std::string::npos) {
            rule.condition.type = YaraCondition::AND;
            // 解析左
            std::string left = c.substr(0, andp);
            std::string right = c.substr(andp + 5);
            auto parseSimple = [&](const std::string& s, YaraCondition& cond) {
                std::string t2 = s;
                auto trimWs = [](std::string& x) {
                    while (!x.empty() && (x[0] == ' ' || x[0] == '\t' || x[0] == '\n' || x[0] == '\r' || x[0] == '('))
                        x = x.substr(1);
                    while (!x.empty() && (x.back() == ' ' || x.back() == '\t' || x.back() == '\n' || x.back() == '\r' || x.back() == ')'))
                        x.pop_back();
                };
                trimWs(t2);
                if (t2 == "any of them") { cond.type = YaraCondition::ANY_OF; }
                else if (t2 == "all of them") { cond.type = YaraCondition::ALL_OF; }
                else if (t2.find(" of them") != std::string::npos) {
                    cond.type = YaraCondition::COUNT_OF;
                    cond.count = std::stoul(t2);
                } else if (!t2.empty() && t2[0] == '$') {
                    cond.type = YaraCondition::SINGLE;
                    cond.ids.push_back(t2);
                }
            };
            rule.condition.left = new YaraCondition();
            rule.condition.right = new YaraCondition();
            parseSimple(left, *rule.condition.left);
            parseSimple(right, *rule.condition.right);
        } else {
            std::string t2 = c;
            // 完整 trim（含换行/制表符/括号）
            auto trimWs = [](std::string& s) {
                while (!s.empty() && (s[0] == ' ' || s[0] == '\t' || s[0] == '\n' || s[0] == '\r' || s[0] == '('))
                    s = s.substr(1);
                while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r' || s.back() == ')'))
                    s.pop_back();
            };
            trimWs(t2);
            if (t2 == "any of them") rule.condition.type = YaraCondition::ANY_OF;
            else if (t2 == "all of them") rule.condition.type = YaraCondition::ALL_OF;
            else if (t2.find(" of them") != std::string::npos) {
                rule.condition.type = YaraCondition::COUNT_OF;
                rule.condition.count = std::stoul(t2);
            } else if (!t2.empty() && t2[0] == '$') {
                rule.condition.type = YaraCondition::SINGLE;
                rule.condition.ids.push_back(t2);
            } else {
                rule.condition.type = YaraCondition::NONE;
            }
        }
    }
    return true;
}

inline void YaraEngine::matchString(const std::vector<uint8_t>& data, YaraString& s) {
    if (s.bytes.empty() || data.size() < s.bytes.size()) return;
    for (size_t i = 0; i + s.bytes.size() <= data.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < s.bytes.size(); ++j) {
            if (s.mask[j] && data[i + j] != s.bytes[j]) { match = false; break; }
        }
        if (match) { s.found = true; return; }
    }
}

inline bool YaraEngine::evalCondition(const YaraCondition& cond, const std::vector<YaraString>& strs) {
    switch (cond.type) {
    case YaraCondition::SINGLE:
        for (const auto& s : strs)
            if (s.found && ("$" + s.id) == cond.ids[0]) return true;
        return false;
    case YaraCondition::ANY_OF:
        for (const auto& s : strs) if (s.found) return true;
        return false;
    case YaraCondition::ALL_OF:
        for (const auto& s : strs) if (!s.found) return false;
        return !strs.empty();
    case YaraCondition::COUNT_OF: {
        size_t n = 0;
        for (const auto& s : strs) if (s.found) n++;
        return n >= cond.count;
    }
    case YaraCondition::AND:
        return evalCondition(*cond.left, strs) && evalCondition(*cond.right, strs);
    default:
        return false;
    }
}

inline std::vector<std::string> YaraEngine::scan(const std::vector<uint8_t>& data) {
    std::vector<std::string> hits;
    for (auto& rule : rules_) {
        // 匹配所有字符串
        for (auto& s : rule.strings) {
            s.found = false;
            matchString(data, s);
        }
        if (evalCondition(rule.condition, rule.strings)) {
            rule.matched = true;
            hits.push_back(rule.name);
        } else {
            rule.matched = false;
        }
    }
    return hits;
}

} // namespace av
