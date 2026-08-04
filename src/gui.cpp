// gui.cpp — 方块杀毒 BlockAV 图形界面（Win32，Unicode 版）
// 功能: 选择目录 -> 扫描 -> 进度条 -> 结果列表 -> 隔离威胁

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <sstream>
#include <filesystem>

#include "scanner.h"
#include "heuristic.h"
#include "quarantine.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

using namespace av;

// 窗口消息（用户自定义）
#define WM_SCAN_PROGRESS (WM_APP + 1)   // wParam = 已扫描数
#define WM_SCAN_THREAT   (WM_APP + 2)   // wParam = 列表索引
#define WM_SCAN_DONE     (WM_APP + 3)   // 扫描完成

// 控件 ID
enum {
    IDC_PATH_EDIT = 1001,
    IDC_BROWSE,
    IDC_SCAN_BTN,
    IDC_STOP_BTN,
    IDC_QUARANTINE_BTN,
    IDC_HEURISTIC_CHECK,
    IDC_PROGRESS,
    IDC_LIST,
    IDC_STATUS,
};

struct AppState {
    HWND hEdit, hBrowse, hProgress, hList, hStatus;
    HWND hScanBtn, hStopBtn, hQuarantineBtn, hHeuristicCheck;
    std::vector<ScanResult> results;
    std::thread scanThread;
    std::atomic<bool> scanning{false};
    std::atomic<bool> stopRequested{false};
    std::atomic<bool> heuristicEnabled{true};  // 默认启用启发式
    Scanner* scanner = nullptr;
    Quarantine* quarantine = nullptr;
    size_t totalFiles = 0;
    size_t infectedCount = 0;
};

static AppState g;

// ---------- 工具函数 ----------

// UTF-8 -> UTF-16（用于把 ScanResult.path 转成宽字符显示）
static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring w(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// UTF-16 -> UTF-8（用于把用户输入的宽字符路径转成 scanner 用的 UTF-8）
static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, NULL, NULL);
    return s;
}

// 添加一行到结果列表（宽字符）
static void addListItem(const wchar_t* col1, const wchar_t* col2, bool highlight) {
    LVITEMW item = {0};
    item.mask = LVIF_TEXT;
    item.pszText = (LPWSTR)col1;
    int idx = ListView_GetItemCount(g.hList);
    item.iItem = idx;
    ListView_InsertItem(g.hList, &item);
    ListView_SetItemText(g.hList, idx, 1, (LPWSTR)col2);
    if (highlight) ListView_SetItemState(g.hList, idx, LVIS_SELECTED, LVIS_SELECTED);
}

static void setStatus(const wchar_t* text) {
    SetWindowTextW(g.hStatus, text);
}

// ---------- 扫描线程 ----------

static void scanThreadFunc(const std::string& path) {
    // 先统计文件总数（用于进度条）
    size_t total = 0;
    {
        std::error_code ec;
        if (std::filesystem::is_directory(path, ec)) {
            for (auto it = std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied, ec);
                 it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (it->is_regular_file(ec)) total++;
            }
        } else if (std::filesystem::is_regular_file(path, ec)) {
            total = 1;
        }
    }
    g.totalFiles = total;
    PostMessageW(GetParent(g.hList), WM_SCAN_PROGRESS, (WPARAM)0, 0);

    // 手动遍历扫描：特征库匹配 + 启发式检测
    std::vector<ScanResult> results;
    size_t count = 0;
    HeuristicEngine heuristic;

    auto processFile = [&](const std::filesystem::path& fpath) {
        if (g.stopRequested) return;
        count++;
        PostMessageW(GetParent(g.hList), WM_SCAN_PROGRESS, (WPARAM)count, 0);

        // 1) 特征库扫描
        ScanResult r;
        g.scanner->scanFile(fpath, r);
        if (r.infected) {
            results.push_back(r);
            return;
        }
        // 2) 启发式检测（识别未知可疑文件）
        if (g.heuristicEnabled) {
            std::error_code ec;
            auto size = std::filesystem::file_size(fpath, ec);
            if (ec || size == 0 || size > 8 * 1024 * 1024) return;  // 限制文件大小
            std::ifstream f(fpath, std::ios::binary);
            if (!f) return;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            if (data.size() > 2 * 1024 * 1024) data.resize(2 * 1024 * 1024);
            auto hr = heuristic.analyze(fpath.string(), data);
            if (hr.level == HeuristicLevel::Malicious || hr.level == HeuristicLevel::Suspicious) {
                r.infected = true;
                // 标记为启发式发现，附上原因
                std::string reasons;
                for (size_t i = 0; i < hr.reasons.size() && i < 2; ++i) {
                    if (!reasons.empty()) reasons += " | ";
                    reasons += hr.reasons[i];
                }
                r.threat = std::string("[启发式]") + (hr.level == HeuristicLevel::Malicious ? "高风险" : "可疑") +
                           " (评分" + std::to_string(hr.score) + ") " + reasons;
                results.push_back(r);
            }
        }
    };

    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        for (auto it = std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied, ec);
             it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (it->is_regular_file(ec)) processFile(it->path());
        }
    } else if (std::filesystem::is_regular_file(path, ec)) {
        processFile(path);
    }
    g.results = results;

    // 发送威胁和完成消息
    size_t infected = 0;
    for (size_t i = 0; i < results.size(); ++i) {
        if (results[i].infected) {
            infected++;
            PostMessageW(GetParent(g.hList), WM_SCAN_THREAT, (WPARAM)i, 0);
        }
    }
    g.infectedCount = infected;
    PostMessageW(GetParent(g.hList), WM_SCAN_DONE, infected, results.size());
}

// ---------- 窗口过程 ----------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);

        CreateWindowW(L"STATIC", L"扫描目录:", WS_CHILD | WS_VISIBLE,
                      10, 10, 70, 24, hwnd, NULL, hInst, NULL);
        g.hEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                85, 10, 380, 26, hwnd, (HMENU)IDC_PATH_EDIT, hInst, NULL);
        g.hScanBtn = CreateWindowW(L"BUTTON", L"开始扫描", WS_CHILD | WS_VISIBLE,
                                   475, 10, 90, 26, hwnd, (HMENU)IDC_SCAN_BTN, hInst, NULL);
        g.hStopBtn = CreateWindowW(L"BUTTON", L"停止", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                   570, 10, 60, 26, hwnd, (HMENU)IDC_STOP_BTN, hInst, NULL);
        g.hBrowse = CreateWindowW(L"BUTTON", L"浏览...", WS_CHILD | WS_VISIBLE,
                                  635, 10, 70, 26, hwnd, (HMENU)IDC_BROWSE, hInst, NULL);

        // 启发式检测复选框（默认勾选）
        g.hHeuristicCheck = CreateWindowW(L"BUTTON", L"启用启发式检测（识别未知可疑文件）",
                                          WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                          10, 68, 330, 22, hwnd, (HMENU)IDC_HEURISTIC_CHECK, hInst, NULL);
        SendMessageW(g.hHeuristicCheck, BM_SETCHECK, BST_CHECKED, 0);

        g.hProgress = CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
                                    10, 45, 695, 20, hwnd, (HMENU)IDC_PROGRESS, hInst, NULL);
        SendMessageW(g.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 10000));

        g.hList = CreateWindowW(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER |
                                LVS_REPORT | LVS_SINGLESEL,
                                10, 95, 695, 360, hwnd, (HMENU)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g.hList, LVS_EX_FULLROWSELECT);
        LVCOLUMNW col;
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 480;
        col.pszText = (LPWSTR)L"文件";
        ListView_InsertColumn(g.hList, 0, &col);
        col.cx = 200;
        col.pszText = (LPWSTR)L"威胁";
        ListView_InsertColumn(g.hList, 1, &col);

        g.hQuarantineBtn = CreateWindowW(L"BUTTON", L"隔离选中", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                         10, 465, 90, 28, hwnd, (HMENU)IDC_QUARANTINE_BTN, hInst, NULL);
        g.hStatus = CreateWindowW(L"STATIC", L"就绪 - 请选择要扫描的目录", WS_CHILD | WS_VISIBLE,
                                  110, 465, 595, 28, hwnd, (HMENU)IDC_STATUS, hInst, NULL);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_BROWSE) {
            BROWSEINFOW bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = L"选择要扫描的目录";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                wchar_t path[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, path))
                    SetWindowTextW(g.hEdit, path);
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_SCAN_BTN) {
            if (g.scanning) return 0;
            wchar_t path[MAX_PATH];
            GetWindowTextW(g.hEdit, path, MAX_PATH);
            if (wcslen(path) == 0) {
                MessageBoxW(hwnd, L"请先选择扫描目录", L"提示", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            // 读取启发式开关状态
            g.heuristicEnabled = (SendMessageW(g.hHeuristicCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            ListView_DeleteAllItems(g.hList);
            g.results.clear();
            g.infectedCount = 0;
            SendMessageW(g.hProgress, PBM_SETPOS, 0, 0);
            EnableWindow(g.hScanBtn, FALSE);
            EnableWindow(g.hStopBtn, TRUE);
            EnableWindow(g.hQuarantineBtn, FALSE);
            setStatus(L"扫描中...");

            g.scanning = true;
            g.stopRequested = false;
            std::string pathStr = wideToUtf8(path);
            g.scanThread = std::thread(scanThreadFunc, pathStr);
        }
        else if (id == IDC_STOP_BTN) {
            g.stopRequested = true;
            setStatus(L"正在停止...");
        }
        else if (id == IDC_QUARANTINE_BTN) {
            int sel = ListView_GetNextItem(g.hList, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g.results.size()) {
                std::string out;
                if (g.quarantine->quarantine(g.results[sel].path, g.results[sel].threat, out)) {
                    g.results[sel].infected = false;
                    std::wstring msg = L"已隔离: " + utf8ToWide(out);
                    setStatus(msg.c_str());
                    ListView_SetItemText(g.hList, sel, 1, (LPWSTR)L"[已隔离]");
                }
            }
        }
        return 0;
    }

    case WM_SCAN_PROGRESS: {
        size_t done = (size_t)wParam;
        size_t total = g.totalFiles ? g.totalFiles : 1;
        SendMessageW(g.hProgress, PBM_SETPOS, (WPARAM)(done * 10000 / total), 0);
        return 0;
    }
    case WM_SCAN_THREAT: {
        size_t idx = (size_t)wParam;
        if (idx < g.results.size()) {
            addListItem(utf8ToWide(g.results[idx].path).c_str(),
                        utf8ToWide(g.results[idx].threat).c_str(), true);
        }
        return 0;
    }
    case WM_SCAN_DONE: {
        size_t infected = (size_t)wParam;
        size_t total = (size_t)lParam;
        g.scanning = false;
        EnableWindow(g.hScanBtn, TRUE);
        EnableWindow(g.hStopBtn, FALSE);
        if (g.scanThread.joinable()) g.scanThread.join();
        std::wstring msg = L"扫描完成: " + std::to_wstring(total) + L" 个文件, 发现 " +
                           std::to_wstring(infected) + L" 个威胁" +
                           (g.stopRequested ? L" (已停止)" : L"");
        setStatus(msg.c_str());
        EnableWindow(g.hQuarantineBtn, infected > 0 ? TRUE : FALSE);
        return 0;
    }

    case WM_DESTROY:
        if (g.scanThread.joinable()) {
            g.stopRequested = true;
            g.scanThread.join();
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------- 入口 ----------

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    // 加载病毒库
    SignatureDB db;
    size_t loaded = 0;
    {
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator("database", ec)) {
            auto ext = entry.path().extension().string();
            if (ext == ".hdb" || ext == ".ndb") {
                size_t before = db.totalCount();
                if (db.loadFromFile(entry.path().string()))
                    loaded += db.totalCount() - before;
            }
        }
    }
    Scanner scanner(db);
    Quarantine q("quarantine");
    g.scanner = &scanner;
    g.quarantine = &q;

    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"BlockAVWindow";
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(L"BlockAVWindow", L"方块杀毒 BlockAV - 图形界面",
                              WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                              CW_USEDEFAULT, CW_USEDEFAULT, 725, 540,
                              NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        MessageBoxW(NULL, L"窗口创建失败", L"错误", MB_OK | MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
