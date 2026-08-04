// main.cpp — 方块杀毒 (Block AV) 命令行入口
//
// 用法:
//   blockav scan <路径>           扫描文件或目录
//   blockav update <签名库目录>   加载病毒库（hdb/ndb 文件）
//   blockav quarantine <文件>     查看/管理隔离区
//   blockav list                  列出已加载的签名
//
// 命令示例:
//   blockav update database
//   blockav scan C:\Users\you\Downloads
//   blockav scan C:\path\test.exe
//   blockav quarantine --list

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <atomic>
#include <filesystem>
#include "signatures.h"
#include "scanner.h"
#include "heuristic.h"
#include "quarantine.h"
#include "md5.h"
#include "monitor.h"
#include "whitelist.h"
#include "yara.h"

namespace fs = std::filesystem;

static void printBanner() {
    std::cout << "=========================================\n";
    std::cout << "   二伯杀毒 ErBaiAV v1.0 (C++学习项目)\n";
    std::cout << "   特征库: ClamAV 格式 | 启发式: 内置\n";
    std::cout << "=========================================\n";
}

static void printUsage() {
    std::cout <<
        "用法:\n"
        "  blockav update <库目录>            加载签名库 (*.hdb / *.ndb)\n"
        "  blockav scan <文件或目录> [--heu]  扫描（--heu 开启启发式, 默认多线程）\n"
        "  blockav scan --db <库目录> <路径>  指定库扫描\n"
        "  blockav monitor <目录> [--quarantine] 实时监控目录（新文件自动扫描）\n"
        "  blockav whitelist --list           列出白名单\n"
        "  blockav whitelist --add <文件>     将文件加入白名单（信任，不再报警）\n"
        "  blockav whitelist --remove <MD5>   从白名单移除\n"
        "  blockav yara <规则.yar> <文件/目录> 用 YARA 规则扫描\n"
        "  blockav quarantine --list          列出隔离区\n"
        "  blockav quarantine --restore <文件> 从隔离区恢复\n"
        "  blockav info                       显示已加载签名统计\n";
}

// 加载签名库目录（返回加载的签名数）
static size_t loadDatabase(av::SignatureDB& db, const std::string& dir) {
    db.clear();
    size_t loaded = 0;
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        std::cerr << "[错误] 目录不存在: " << dir << std::endl;
        return 0;
    }
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        auto ext = entry.path().extension().string();
        if (ext == ".hdb" || ext == ".ndb" || ext == ".hdu" || ext == ".ndu") {
            size_t before = db.totalCount();
            if (db.loadFromFile(entry.path().string()))
                loaded += db.totalCount() - before;
        }
    }
    return loaded;
}

// 启发式扫描一个文件
static void heuristicScanFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "[启发式] 无法读取: " << path << std::endl; return; }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (data.size() > 2 * 1024 * 1024) data.resize(2 * 1024 * 1024);

    av::HeuristicEngine heu;
    auto r = heu.analyze(path, data);
    if (r.level != av::HeuristicLevel::Clean) {
        std::cout << "[启发式] " << path << " 风险等级: "
                  << (r.level == av::HeuristicLevel::Malicious ? "高(恶意)" : "中(可疑)")
                  << " 评分: " << r.score << std::endl;
        for (const auto& reason : r.reasons)
            std::cout << "         - " << reason << std::endl;
    } else {
        std::cout << "[启发式] " << path << " 干净" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    printBanner();
    if (argc < 2) { printUsage(); return 0; }

    std::string cmd = argv[1];
    av::SignatureDB db;
    std::string dbDir = "database";

    if (cmd == "update" || cmd == "load") {
        if (argc >= 3) dbDir = argv[2];
        size_t n = loadDatabase(db, dbDir);
        std::cout << "[更新] 共加载 " << n << " 条签名" << std::endl;
        return 0;
    }
    else if (cmd == "info") {
        if (argc >= 3) dbDir = argv[2];
        loadDatabase(db, dbDir);
        std::cout << "[信息] HDB(哈希): " << db.hashCount()
                  << " | NDB(特征): " << db.hexCount() << std::endl;
        return 0;
    }
    else if (cmd == "scan") {
        // 解析参数
        bool useHeuristic = false;
        std::string target;
        for (int i = 2; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--heu") useHeuristic = true;
            else if (a == "--db" && i + 1 < argc) { dbDir = argv[++i]; }
            else target = a;
        }
        if (target.empty()) { std::cerr << "[错误] 需要扫描路径" << std::endl; return 1; }

        size_t sigs = loadDatabase(db, dbDir);
        std::cout << "[扫描] 签名库: " << sigs << " 条 | 目标: " << target << std::endl;

        av::Scanner scanner(db);
        av::Whitelist wl("whitelist.txt");
        scanner.setWhitelist(&wl);

        std::vector<av::ScanResult> results;
        std::atomic<size_t> done{0};
        size_t threads = av::Scanner::defaultThreadCount();
        std::cout << "[扫描] 线程数: " << threads << " (并行加速)\n";
        scanner.scanDirectoryParallel(target, results, threads, [&](const av::ScanResult&) {
            size_t d = done.fetch_add(1) + 1;
            if (d % 200 == 0) std::cout << "  已扫描 " << d << " 个文件...\r" << std::flush;
        });
        std::cout << std::endl;

        // 输出感染文件
        size_t infected = 0;
        for (const auto& r : results) {
            if (r.infected) {
                std::cout << "  [威胁] " << r.path << " -> " << r.threat << std::endl;
                infected++;
            } else if (useHeuristic) {
                // 启发式：只对未被特征库命中的文件做二次检查
                std::ifstream f(r.path, std::ios::binary);
                if (f) {
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                    if (data.size() > 2 * 1024 * 1024) data.resize(2 * 1024 * 1024);
                    av::HeuristicEngine heu;
                    auto hr = heu.analyze(r.path, data);
                    if (hr.level == av::HeuristicLevel::Malicious) {
                        std::cout << "  [启发式威胁] " << r.path << " (评分 " << hr.score << ")" << std::endl;
                        for (const auto& reason : hr.reasons)
                            std::cout << "      - " << reason << std::endl;
                        infected++;
                    }
                }
            }
        }

        std::cout << "\n[结果] 扫描 " << scanner.stats().filesScanned << " 个文件, "
                  << "感染 " << infected << " 个, 错误 " << scanner.stats().errors << std::endl;
        return infected > 0 ? 2 : 0;
    }
    else if (cmd == "monitor") {
        if (argc < 3) { std::cerr << "[错误] 用法: blockav monitor <目录> [--quarantine]" << std::endl; return 1; }
        std::string target = argv[2];
        bool autoQuarantine = false;
        for (int i = 3; i < argc; ++i) if (std::string(argv[i]) == "--quarantine") autoQuarantine = true;

        size_t sigs = loadDatabase(db, dbDir);
        std::cout << "[监控] 签名库: " << sigs << " 条" << std::endl;

        av::Scanner scanner(db);
        av::Quarantine q("quarantine");
        av::FileMonitor monitor(target, scanner,
            [&](const std::string& path, const std::string& threat) {
                if (autoQuarantine) {
                    std::string out;
                    q.quarantine(path, threat, out);
                }
            });
        if (!monitor.start()) return 1;
        std::cout << "按 Enter 停止监控..." << std::endl;
        std::cin.get();
        monitor.stop();
        return 0;
    }
    else if (cmd == "whitelist") {
        av::Whitelist wl("whitelist.txt");
        if (argc < 3) { wl.list_usage(); return 0; }
        std::string sub = argv[2];
        if (sub == "--list") {
            std::cout << "===== 白名单 (信任文件, 共 " << wl.size() << " 条) =====" << std::endl;
            wl.list();
        } else if (sub == "--add" && argc >= 4) {
            std::string md5 = av::Scanner::fileMd5(argv[3]);
            if (md5.empty()) { std::cerr << "[错误] 无法计算 MD5: " << argv[3] << std::endl; return 1; }
            wl.add(md5);
        } else if (sub == "--remove" && argc >= 4) {
            wl.remove(argv[3]);
        } else {
            std::cout << "用法: blockav whitelist --list | --add <文件> | --remove <MD5>" << std::endl;
        }
        return 0;
    }
    else if (cmd == "yara") {
        if (argc < 4) {
            std::cerr << "[错误] 用法: blockav yara <规则.yar> <文件/目录>" << std::endl;
            return 1;
        }
        av::YaraEngine engine;
        if (!engine.loadFromFile(argv[2])) return 1;
        std::string target = argv[3];

        std::vector<fs::path> files;
        av::Scanner::collectFiles(target, files);
        std::cout << "[YARA] 扫描 " << files.size() << " 个文件..." << std::endl;

        size_t hits = 0;
        for (const auto& f : files) {
            std::error_code ec;
            auto size = fs::file_size(f, ec);
            if (ec || size == 0 || size > 16 * 1024 * 1024) continue;
            std::ifstream in(f, std::ios::binary);
            if (!in) continue;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            auto matched = engine.scan(data);
            if (!matched.empty()) {
                for (const auto& r : matched)
                    std::cout << "  [YARA] " << f.string() << " -> " << r << std::endl;
                hits++;
            }
        }
        std::cout << "[结果] YARA 命中 " << hits << " 个文件" << std::endl;
        return hits > 0 ? 2 : 0;
    }
    else if (cmd == "quarantine") {
        av::Quarantine q("quarantine");
        if (argc >= 3 && std::string(argv[2]) == "--list") { q.list(); return 0; }
        if (argc >= 4 && std::string(argv[2]) == "--restore") {
            std::string restored;
            q.restore(argv[3], restored);
            return 0;
        }
        if (argc >= 3 && std::string(argv[2]) == "--add" && argc >= 4) {
            std::string out;
            q.quarantine(argv[3], "manual", out);
            return 0;
        }
        std::cout << "用法: blockav quarantine --list | --restore <文件> | --add <文件>" << std::endl;
        return 0;
    }
    else if (cmd == "help" || cmd == "-h" || cmd == "--help") {
        printUsage();
        return 0;
    }

    std::cerr << "[错误] 未知命令: " << cmd << std::endl;
    printUsage();
    return 1;
}
