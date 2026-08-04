# 🛡️ 方块杀毒 BlockAV v0.1

一个用 **C++ 编写**的 Windows 杀毒引擎（学习项目），实现了卡巴斯基同款技术栈的核心功能：
特征库查杀 + 启发式分析 + 隔离区管理。

> ⚠️ **诚实说明**：这是一个学习项目，不是商业级杀毒软件。
> 它演示了杀毒引擎的核心原理，但**不具备卡巴斯基级别的防护能力**
> （病毒库规模、云查杀、行为监控等需要巨大投入）。

---

## ✨ 已实现功能

| 功能 | 原理 | 对应商业产品能力 |
|------|------|----------------|
| 🔍 文件/目录扫描 | 递归遍历 + 逐文件分析 | 手动扫描 |
| 🧬 HDB 哈希匹配 | MD5:文件大小:病毒名 精确比对 | 病毒库检测 |
| 🔑 NDB 特征匹配 | 十六进制签名（支持 ?? 通配） | 特征码查杀 |
| 🕵️ 启发式检测 | PE 文件分析 + 危险 API + 熵检测 | 启发式引擎 |
| 🧊 隔离区 | 移动文件 + 元数据记录 + 恢复 | 隔离中心 |
| 📋 扫描报告 | 感染统计 + 退出码 | 报告系统 |
| 🛰️ **实时监控** | ReadDirectoryChangesW 监视目录变化 | 实时保护 |
| 🖥️ **图形界面** | Win32 GUI（进度条/结果列表/一键隔离） | 用户界面 |
| 📥 **ClamAV 病毒库** | 官方 CVD 库解析 + 自动更新脚本 | 病毒库更新 |

## 🗂️ 项目结构

```
antivirus-cpp/
├── src/
│   ├── main.cpp        入口（命令分发）
│   ├── signatures.h    ClamAV 特征库解析（HDB/NDB）
│   ├── scanner.h       扫描引擎
│   ├── heuristic.h     启发式检测引擎
│   ├── quarantine.h    隔离区管理
│   └── md5.h           轻量 MD5 实现（RFC 1321）
├── database/           病毒特征库（*.hdb / *.ndb）
├── quarantine/         隔离区目录
├── test_samples/       测试样本
├── build.py            一键构建（Python 调用 MSVC）
└── build.bat           一键构建（批处理）
```

## 🔨 构建

**依赖**：Visual Studio Build Tools 2022（MSVC 14.44 + Windows SDK 10.0.26100）

```bat
:: 命令行版
python build.py

:: 图形界面版（GUI）
python build_gui.py

:: 下载并更新 ClamAV 官方病毒库（自动生成 database/ 特征文件）
python update_database.py --daily --main
```

## 🚀 使用

```bat
:: 加载特征库
blockav.exe update database

:: 扫描文件或目录（--heu 开启启发式）
blockav.exe scan C:\Users\you\Downloads --heu
blockav.exe scan C:\path\test.exe

:: 实时监控目录（新文件出现自动扫描，--quarantine 自动隔离）
blockav.exe monitor C:\Users\you\Downloads --quarantine

:: 图形界面（双击运行）
blockav_gui.exe

:: 隔离区管理
blockav.exe quarantine --list
blockav.exe quarantine --add <文件>
blockav.exe quarantine --restore <隔离文件>

:: 显示签名统计
blockav.exe info database
```

**退出码**：`0` = 干净，`2` = 发现威胁

## 🧬 特征库格式（ClamAV 标准）

**HDB**（哈希签名）：
```
<文件MD5>:<文件大小>:<病毒名>
44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test-File
```

**NDB**（十六进制特征签名）：
```
<病毒名>:<目标类型>:<偏移>:<十六进制签名>
EICAR-Test-NDB:0:*:58354f2150254041505b345c505a583534
```

- 目标类型：`0`=任意, `1`=PE, `2`=ELF, `3`=Mach-O
- 偏移：`*` = 任意位置
- 支持 `??` 通配字节

> 💡 可以直接下载 **ClamAV 的开源特征库**（database.clamav.net），
> 把 .hdb/.ndb 文本文件放入 `database/` 目录即可扩展检测能力。

## 🕵️ 启发式检测规则

1. **PE 文件分析**：解析 MZ/PE 头，检测可疑节区名（UPX、pack 等）
2. **危险 API 检测**：CreateRemoteThread、WriteProcessMemory、VirtualAllocEx、
   GetAsyncKeyState、CryptEncrypt 等 15 种恶意行为特征
3. **加壳检测**：文件内容高熵（>7.5）判定为疑似混淆

评分 ≥5 判定恶意，≥2 判定可疑。

## 📌 已知限制（与卡巴斯基的差距）

- 单线程扫描（卡巴斯基多线程 + 云查杀）
- 病毒库需手动更新（卡巴斯基每分钟自动更新数亿条签名）
- 不支持 LDB 逻辑签名 / MDB 元签名（ClamAV 复杂格式，约 270 万条）
- 无行为沙箱、无进程监控、无内核保护
- MD5 哈希有理论碰撞风险（商业产品用更稳健的指纹）

## 🔭 后续规划

- [x] CVD 病毒库解析（ClamAV 官方库，12 万+ 条签名）
- [x] 实时文件监控（ReadDirectoryChangesW）
- [x] Win32 GUI（图形界面）
- [ ] LDB/MDB 复杂签名格式支持（另 270 万条）
- [ ] 内存扫描 + 进程枚举
- [ ] 扫描白名单 / 性能优化（多线程）

---

*学习用途。请勿用于恶意目的。*
