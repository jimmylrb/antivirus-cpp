// gui.cpp — 方块杀毒 BlockAV 图形界面（Win32）
// 功能: 选择目录 -> 扫描 -> 进度条 -> 结果列表 -> 隔离威胁
//
// 编译: 见 build_gui.py（链接 user32.lib comctl32.lib comdlg32.lib）

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
#include "quarantine.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

using namespace av;

// 窗口消息（用户自定义）
#define WM_SCAN_PROGRESS (WM_APP + 1)   // wParam = 已扫描数
#define WM_SCAN_THREAT   (WM_APP + 2)   // wParam = 列表索引
#define WM_SCAN_DONE     (WM_APP + 3)   // 扫描完成
#define WM_SCAN_ERROR    (WM_APP + 4)   // 扫描出错

// 控件 ID
enum {
    IDC_PATH_EDIT = 1001,
    IDC_BROWSE,
    IDC_SCAN_BTN,
    IDC_STOP_BTN,
    IDC_QUARANTINE_BTN,
    IDC_PROGRESS,
    IDC_LIST,
    IDC_STATUS,
};

struct AppState {
    HWND hEdit, hBrowse, hProgress, hList, hStatus;
    HWND hScanBtn, hStopBtn, hQuarantineBtn;
    std::vector<ScanResult> results;
    std::thread scanThread;
    std::atomic<bool> scanning{false};
    std::atomic<bool> stopRequested{false};
    Scanner* scanner = nullptr;
    Quarantine* quarantine = nullptr;
    SignatureDB* db = nullptr;
    size_t totalFiles = 0;
    size_t infectedCount = 0;
};

static AppState g;

// ---------- 工具函数 ----------

static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, NULL, NULL);
    return s;
}

static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring w(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// 添加一行到结果列表
static void addListItem(const char* col1, const char* col2, bool highlight) {
    LVITEM item = {0};
    item.mask = LVIF_TEXT;
    item.pszText = (LPSTR)col1;
    int idx = ListView_GetItemCount(g.hList);
    item.iItem = idx;
    ListView_InsertItem(g.hList, &item);
    ListView_SetItemText(g.hList, idx, 1, (LPSTR)col2);
    if (highlight) ListView_SetItemState(g.hList, idx, LVIS_SELECTED, LVIS_SELECTED);
}

static void setStatus(const char* text) {
    SetWindowTextA(g.hStatus, text);
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
    PostMessageA(GetParent(g.hList), WM_SCAN_PROGRESS, (WPARAM)0, 0);

    // 扫描
    std::vector<ScanResult> results;
    size_t count = 0;
    g.scanner->scanDirectory(path, results, [&](const ScanResult&) {
        count++;
        PostMessageA(GetParent(g.hList), WM_SCAN_PROGRESS, (WPARAM)count, 0);
    });
    g.results = results;

    // 发送威胁和完成消息
    size_t infected = 0;
    for (size_t i = 0; i < results.size(); ++i) {
        if (results[i].infected) {
            infected++;
            PostMessageA(GetParent(g.hList), WM_SCAN_THREAT, (WPARAM)i, 0);
        }
    }
    g.infectedCount = infected;
    PostMessageA(GetParent(g.hList), WM_SCAN_DONE, infected, results.size());
}

// ---------- 窗口过程 ----------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // 创建控件
        HINSTANCE hInst = GetModuleHandle(NULL);

        // 标题
        CreateWindowA("STATIC", "扫描目录:", WS_CHILD | WS_VISIBLE,
                      10, 10, 70, 24, hwnd, NULL, hInst, NULL);
        g.hEdit = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                85, 10, 380, 26, hwnd, (HMENU)IDC_PATH_EDIT, hInst, NULL);
        g.hScanBtn = CreateWindowA("BUTTON", "开始扫描", WS_CHILD | WS_VISIBLE,
                                   475, 10, 90, 26, hwnd, (HMENU)IDC_SCAN_BTN, hInst, NULL);
        g.hStopBtn = CreateWindowA("BUTTON", "停止", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                   570, 10, 60, 26, hwnd, (HMENU)IDC_STOP_BTN, hInst, NULL);

        g.hBrowse = CreateWindowA("BUTTON", "浏览...", WS_CHILD | WS_VISIBLE,
                                  635, 10, 70, 26, hwnd, (HMENU)IDC_BROWSE, hInst, NULL);

        // 进度条
        g.hProgress = CreateWindowA(PROGRESS_CLASS, "", WS_CHILD | WS_VISIBLE,
                                    10, 45, 695, 20, hwnd, (HMENU)IDC_PROGRESS, hInst, NULL);
        SendMessage(g.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 10000));

        // 结果列表
        g.hList = CreateWindowA(WC_LISTVIEW, "", WS_CHILD | WS_VISIBLE | WS_BORDER |
                                LVS_REPORT | LVS_SINGLESEL,
                                10, 75, 695, 380, hwnd, (HMENU)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g.hList, LVS_EX_FULLROWSELECT);
        LVCOLUMN col;
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 480;
        col.pszText = (LPSTR)"文件";
        ListView_InsertColumn(g.hList, 0, &col);
        col.cx = 200;
        col.pszText = (LPSTR)"威胁";
        ListView_InsertColumn(g.hList, 1, &col);

        // 隔离按钮 + 状态栏
        g.hQuarantineBtn = CreateWindowA("BUTTON", "隔离选中", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                         10, 465, 90, 28, hwnd, (HMENU)IDC_QUARANTINE_BTN, hInst, NULL);
        g.hStatus = CreateWindowA("STATIC", "就绪 - 请选择要扫描的目录", WS_CHILD | WS_VISIBLE,
                                  110, 465, 595, 28, hwnd, (HMENU)IDC_STATUS, hInst, NULL);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == IDC_BROWSE) {
            // 选择目录对话框
            BROWSEINFOA bi = {0};
            bi.hwndOwner = hwnd;
            bi.lpszTitle = "选择要扫描的目录";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
            if (pidl) {
                char path[MAX_PATH];
                if (SHGetPathFromIDListA(pidl, path))
                    SetWindowTextA(g.hEdit, path);
                CoTaskMemFree(pidl);
            }
        }
        else if (id == IDC_SCAN_BTN) {
            if (g.scanning) return 0;
            char path[MAX_PATH];
            GetWindowTextA(g.hEdit, path, MAX_PATH);
            if (strlen(path) == 0) {
                MessageBoxA(hwnd, "请先选择扫描目录", "提示", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            // 清空列表
            ListView_DeleteAllItems(g.hList);
            g.results.clear();
            g.infectedCount = 0;
            SendMessage(g.hProgress, PBM_SETPOS, 0, 0);
            EnableWindow(g.hScanBtn, FALSE);
            EnableWindow(g.hStopBtn, TRUE);
            EnableWindow(g.hQuarantineBtn, FALSE);
            setStatus("扫描中...");

            g.scanning = true;
            g.stopRequested = false;
            std::string pathStr(path);
            g.scanThread = std::thread(scanThreadFunc, pathStr);
        }
        else if (id == IDC_STOP_BTN) {
            g.stopRequested = true;
            setStatus("正在停止...");
        }
        else if (id == IDC_QUARANTINE_BTN) {
            int sel = ListView_GetNextItem(g.hList, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g.results.size()) {
                std::string out;
                if (g.quarantine->quarantine(g.results[sel].path, g.results[sel].threat, out)) {
                    g.results[sel].infected = false;
                    setStatus(("已隔离: " + out).c_str());
                    ListView_SetItemText(g.hList, sel, 1, (LPSTR)"[已隔离]");
                }
            }
        }
        return 0;
    }

    case WM_SCAN_PROGRESS: {
        size_t done = (size_t)wParam;
        size_t total = g.totalFiles ? g.totalFiles : 1;
        SendMessage(g.hProgress, PBM_SETPOS, (WPARAM)(done * 10000 / total), 0);
        return 0;
    }
    case WM_SCAN_THREAT: {
        size_t idx = (size_t)wParam;
        if (idx < g.results.size()) {
            addListItem(g.results[idx].path.c_str(), g.results[idx].threat.c_str(), true);
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
        std::ostringstream oss;
        oss << "扫描完成: " << total << " 个文件, 发现 " << infected << " 个威胁"
            << (g.stopRequested ? " (已停止)" : "");
        setStatus(oss.str().c_str());
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
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ---------- 入口 ----------

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // 初始化公共控件
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    // 加载病毒库
    SignatureDB db;
    // 扫描 database/ 目录下所有 .hdb/.ndb
    {
        std::error_code ec;
        size_t loaded = 0;
        for (const auto& entry : std::filesystem::directory_iterator("database", ec)) {
            auto ext = entry.path().extension().string();
            if (ext == ".hdb" || ext == ".ndb") {
                size_t before = db.totalCount();
                if (db.loadFromFile(entry.path().string()))
                    loaded += db.totalCount() - before;
            }
        }
        MessageBoxA(NULL, ("病毒库加载完成: " + std::to_string(loaded) + " 条签名").c_str(),
                    "方块杀毒 BlockAV", MB_OK | MB_ICONINFORMATION);
    }
    Scanner scanner(db);
    Quarantine q("quarantine");
    g.scanner = &scanner;
    g.quarantine = &q;
    g.db = &db;

    // 注册窗口类
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "BlockAVWindow";
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassA(&wc);

    // 创建窗口
    HWND hwnd = CreateWindowA("BlockAVWindow", "方块杀毒 BlockAV - 图形界面",
                              WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                              CW_USEDEFAULT, CW_USEDEFAULT, 725, 540,
                              NULL, NULL, hInstance, NULL);
    if (!hwnd) {
        MessageBoxA(NULL, "窗口创建失败", "错误", MB_OK | MB_ICONERROR);
        return 1;
    }
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
