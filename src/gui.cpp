// gui.cpp — 方块杀毒 BlockAV 图形界面 v3（DPI 感知，高分屏清晰）
// 深色横幅 + 品牌渐变 + 威胁分级着色 + 扫描统计 + 启发式检测
// v3: 声明 Per-Monitor DPI 感知，所有控件按 DPI 缩放，彻底解决高分屏模糊

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <sstream>
#include <filesystem>
#include <fstream>

#include "scanner.h"
#include "heuristic.h"
#include "quarantine.h"

// 启用 ComCtl32 v6 视觉样式（现代控件外观）
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "msimg32.lib")

using namespace av;

// ============ 主题色 ============
#define CLR_BANNER_1  RGB(0x2D, 0x9C, 0xDB)
#define CLR_BANNER_2  RGB(0x5B, 0x4F, 0xCF)
#define CLR_BANNER_3  RGB(0x8B, 0x5C, 0xF6)
#define CLR_ACCENT    RGB(0x00, 0xC8, 0xFF)
#define CLR_TEXT_ON_BANNER RGB(255, 255, 255)
#define CLR_THREAT    RGB(0xFF, 0x6B, 0x6B)
#define CLR_SUSPICIOUS RGB(0xFF, 0xA9, 0x4D)
#define CLR_PANEL_BG  RGB(0xF5, 0xF7, 0xFA)
#define CLR_BAR       RGB(0x00, 0xB8, 0xE6)

// 布局（逻辑像素 96 DPI，运行时按 g_scale 缩放）
#define BANNER_H     100
#define WORK_TOP     (BANNER_H + 12)

// 窗口消息
#define WM_SCAN_PROGRESS (WM_APP + 1)
#define WM_SCAN_THREAT   (WM_APP + 2)
#define WM_SCAN_DONE     (WM_APP + 3)

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
    IDC_STAT_FILES,
    IDC_STAT_THREATS,
    IDC_STAT_TIME,
    IDC_LOGO,
};

// ============ DPI 缩放 ============
static float g_scale = 1.0f;   // 96 DPI 为基准
static int S(int v) { return (int)(v * g_scale + 0.5f); }

struct AppState {
    HWND hEdit, hBrowse, hProgress, hList, hStatus;
    HWND hScanBtn, hStopBtn, hQuarantineBtn, hHeuristicCheck;
    HWND hStatFiles, hStatThreats, hStatTime, hLogo;
    HFONT hFontTitle, hFontBig, hFontBase, hFontStat, hFontStatNum;
    std::vector<ScanResult> results;
    std::thread scanThread;
    std::atomic<bool> scanning{false};
    std::atomic<bool> stopRequested{false};
    std::atomic<bool> heuristicEnabled{true};
    Scanner* scanner = nullptr;
    Quarantine* quarantine = nullptr;
    size_t totalFiles = 0;
    size_t infectedCount = 0;
    size_t suspiciousCount = 0;
    ULONGLONG scanStartTime = 0;
};

static AppState g;

// ---------- 工具函数 ----------

static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    std::wstring w(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    std::string s(n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, NULL, NULL);
    return s;
}

static void addListItem(const wchar_t* col1, const wchar_t* col2) {
    LVITEMW item = {0};
    item.mask = LVIF_TEXT;
    item.pszText = (LPWSTR)col1;
    int idx = ListView_GetItemCount(g.hList);
    item.iItem = idx;
    ListView_InsertItem(g.hList, &item);
    ListView_SetItemText(g.hList, idx, 1, (LPWSTR)col2);
}

static void setStatus(const wchar_t* text) {
    SetWindowTextW(g.hStatus, text);
}

// 绘制盾牌图标（矢量）
static void drawShield(HDC hdc, int x, int y, int size) {
    HPEN pen = CreatePen(PS_SOLID, S(2), RGB(255, 255, 255));
    HBRUSH br = CreateSolidBrush(RGB(255, 255, 255));
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    HGDIOBJ oldBr = SelectObject(hdc, br);
    BeginPath(hdc);
    MoveToEx(hdc, x, y - size / 2, NULL);
    LineTo(hdc, x + size / 2, y - size / 3);
    LineTo(hdc, x + size / 2, y + size / 6);
    LineTo(hdc, x + size / 3, y + size / 3);
    LineTo(hdc, x, y + size / 2);
    LineTo(hdc, x - size / 3, y + size / 3);
    LineTo(hdc, x - size / 2, y + size / 6);
    LineTo(hdc, x - size / 2, y - size / 3);
    CloseFigure(hdc);
    EndPath(hdc);
    FillPath(hdc);
    HPEN checkPen = CreatePen(PS_SOLID, S(3), CLR_BANNER_1);
    SelectObject(hdc, checkPen);
    MoveToEx(hdc, x - size / 4, y, NULL);
    LineTo(hdc, x - size / 10, y + size / 5);
    LineTo(hdc, x + size / 4, y - size / 5);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBr);
    DeleteObject(pen); DeleteObject(br); DeleteObject(checkPen);
}

// 横幅渐变背景
static void drawBanner(HDC hdc, int width) {
    for (int y = 0; y < S(BANNER_H); ++y) {
        double t = (double)y / S(BANNER_H);
        int r, gg, b;
        if (t < 0.5) {
            double u = t * 2;
            r = (int)((GetRValue(CLR_BANNER_1) * (1 - u) + GetRValue(CLR_BANNER_2) * u));
            gg = (int)((GetGValue(CLR_BANNER_1) * (1 - u) + GetGValue(CLR_BANNER_2) * u));
            b = (int)((GetBValue(CLR_BANNER_1) * (1 - u) + GetBValue(CLR_BANNER_2) * u));
        } else {
            double u = (t - 0.5) * 2;
            r = (int)((GetRValue(CLR_BANNER_2) * (1 - u) + GetRValue(CLR_BANNER_3) * u));
            gg = (int)((GetGValue(CLR_BANNER_2) * (1 - u) + GetGValue(CLR_BANNER_3) * u));
            b = (int)((GetBValue(CLR_BANNER_2) * (1 - u) + GetBValue(CLR_BANNER_3) * u));
        }
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(r, gg, b));
        HGDIOBJ old = SelectObject(hdc, pen);
        MoveToEx(hdc, 0, y, NULL);
        LineTo(hdc, width, y);
        SelectObject(hdc, old);
        DeleteObject(pen);
    }
}

static bool isSuspiciousThreat(const std::string& threat) {
    return threat.find("[启发式]") != std::string::npos;
}

// ---------- 扫描线程 ----------

static void scanThreadFunc(const std::string& path) {
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

    std::vector<ScanResult> results;
    size_t count = 0;
    HeuristicEngine heuristic;

    auto processFile = [&](const std::filesystem::path& fpath) {
        if (g.stopRequested) return;
        count++;
        PostMessageW(GetParent(g.hList), WM_SCAN_PROGRESS, (WPARAM)count, 0);

        ScanResult r;
        g.scanner->scanFile(fpath, r);
        if (r.infected) {
            results.push_back(r);
            return;
        }
        if (g.heuristicEnabled) {
            std::error_code ec;
            auto size = std::filesystem::file_size(fpath, ec);
            if (ec || size == 0 || size > 8 * 1024 * 1024) return;
            std::ifstream f(fpath, std::ios::binary);
            if (!f) return;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            if (data.size() > 2 * 1024 * 1024) data.resize(2 * 1024 * 1024);
            auto hr = heuristic.analyze(fpath.string(), data);
            if (hr.level == HeuristicLevel::Malicious || hr.level == HeuristicLevel::Suspicious) {
                r.infected = true;
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

    size_t infected = 0, suspicious = 0;
    for (size_t i = 0; i < results.size(); ++i) {
        if (results[i].infected) {
            infected++;
            if (isSuspiciousThreat(results[i].threat)) suspicious++;
            PostMessageW(GetParent(g.hList), WM_SCAN_THREAT, (WPARAM)i, 0);
        }
    }
    g.infectedCount = infected;
    g.suspiciousCount = suspicious;
    PostMessageW(GetParent(g.hList), WM_SCAN_DONE, infected, results.size());
}

// ---------- 窗口过程 ----------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);

        // 获取 DPI，计算缩放系数
        UINT dpi = GetDpiForWindow(hwnd);
        g_scale = dpi / 96.0f;

        // 字体（按 DPI 缩放字号）
        g.hFontTitle = CreateFontW(S(26), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontStat = CreateFontW(S(12), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontBase = CreateFontW(S(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontStatNum = CreateFontW(S(22), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");

        // 横幅 Logo + 标题 + 副标题
        g.hLogo = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
                                S(20), S(14), S(72), S(72), hwnd, (HMENU)IDC_LOGO, hInst, NULL);
        HWND hTitle = CreateWindowW(L"STATIC", L"方块杀毒 BlockAV", WS_CHILD | WS_VISIBLE,
                                    S(100), S(20), S(320), S(34), hwnd, NULL, hInst, NULL);
        HWND hSub = CreateWindowW(L"STATIC", L"C++ 杀毒引擎 · ClamAV 病毒库 · 启发式分析",
                                  WS_CHILD | WS_VISIBLE, S(100), S(56), S(420), S(22), hwnd, NULL, hInst, NULL);

        // 统计数字
        g.hStatFiles = CreateWindowW(L"STATIC", L"0", WS_CHILD | WS_VISIBLE,
                                     S(520), S(16), S(70), S(36), hwnd, (HMENU)IDC_STAT_FILES, hInst, NULL);
        CreateWindowW(L"STATIC", L"已扫描", WS_CHILD | WS_VISIBLE, S(520), S(58), S(70), S(20), hwnd, NULL, hInst, NULL);
        g.hStatThreats = CreateWindowW(L"STATIC", L"0", WS_CHILD | WS_VISIBLE,
                                       S(615), S(16), S(70), S(36), hwnd, (HMENU)IDC_STAT_THREATS, hInst, NULL);
        CreateWindowW(L"STATIC", L"威胁", WS_CHILD | WS_VISIBLE, S(615), S(58), S(70), S(20), hwnd, NULL, hInst, NULL);
        g.hStatTime = CreateWindowW(L"STATIC", L"0s", WS_CHILD | WS_VISIBLE,
                                    S(710), S(16), S(70), S(36), hwnd, (HMENU)IDC_STAT_TIME, hInst, NULL);
        CreateWindowW(L"STATIC", L"用时", WS_CHILD | WS_VISIBLE, S(710), S(58), S(70), S(20), hwnd, NULL, hInst, NULL);

        // 工作区
        CreateWindowW(L"STATIC", L"扫描目录:", WS_CHILD | WS_VISIBLE,
                      S(20), S(WORK_TOP), S(70), S(24), hwnd, NULL, hInst, NULL);
        g.hEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                S(90), S(WORK_TOP) - S(2), S(380), S(28), hwnd, (HMENU)IDC_PATH_EDIT, hInst, NULL);
        g.hScanBtn = CreateWindowW(L"BUTTON", L"开始扫描", WS_CHILD | WS_VISIBLE,
                                   S(480), S(WORK_TOP) - S(2), S(100), S(28), hwnd, (HMENU)IDC_SCAN_BTN, hInst, NULL);
        g.hStopBtn = CreateWindowW(L"BUTTON", L"停止", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                   S(585), S(WORK_TOP) - S(2), S(60), S(28), hwnd, (HMENU)IDC_STOP_BTN, hInst, NULL);
        g.hBrowse = CreateWindowW(L"BUTTON", L"浏览...", WS_CHILD | WS_VISIBLE,
                                  S(650), S(WORK_TOP) - S(2), S(70), S(28), hwnd, (HMENU)IDC_BROWSE, hInst, NULL);

        g.hHeuristicCheck = CreateWindowW(L"BUTTON", L"启用启发式检测（识别未知可疑文件）",
                                          WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                          S(20), S(WORK_TOP) + S(34), S(360), S(22), hwnd, (HMENU)IDC_HEURISTIC_CHECK, hInst, NULL);
        SendMessageW(g.hHeuristicCheck, BM_SETCHECK, BST_CHECKED, 0);

        g.hProgress = CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
                                    S(20), S(WORK_TOP) + S(62), S(700), S(12), hwnd, (HMENU)IDC_PROGRESS, hInst, NULL);
        SendMessageW(g.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 10000));
        SendMessageW(g.hProgress, PBM_SETBARCOLOR, 0, (LPARAM)CLR_BAR);
        SendMessageW(g.hProgress, PBM_SETBKCOLOR, 0, (LPARAM)RGB(0xE2, 0xE8, 0xF0));

        g.hList = CreateWindowW(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER |
                                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                S(20), S(WORK_TOP) + S(84), S(700), S(330), hwnd, (HMENU)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g.hList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
        LVCOLUMNW col;
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = S(460);
        col.pszText = (LPWSTR)L"文件";
        ListView_InsertColumn(g.hList, 0, &col);
        col.cx = S(230);
        col.pszText = (LPWSTR)L"检测结果";
        ListView_InsertColumn(g.hList, 1, &col);

        g.hQuarantineBtn = CreateWindowW(L"BUTTON", L"隔离选中", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                         S(20), S(WORK_TOP) + S(424), S(100), S(30), hwnd, (HMENU)IDC_QUARANTINE_BTN, hInst, NULL);
        g.hStatus = CreateWindowW(L"STATIC", L"就绪 - 请选择要扫描的目录", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                  S(130), S(WORK_TOP) + S(424), S(590), S(30), hwnd, (HMENU)IDC_STATUS, hInst, NULL);

        // 应用字体
        SetWindowFont(g.hLogo, g.hFontBase, TRUE);
        SetWindowFont(hTitle, g.hFontTitle, TRUE);
        SetWindowFont(hSub, g.hFontStat, TRUE);
        SetWindowFont(g.hEdit, g.hFontBase, TRUE);
        SetWindowFont(g.hScanBtn, g.hFontBase, TRUE);
        SetWindowFont(g.hStopBtn, g.hFontBase, TRUE);
        SetWindowFont(g.hBrowse, g.hFontBase, TRUE);
        SetWindowFont(g.hHeuristicCheck, g.hFontBase, TRUE);
        SetWindowFont(g.hList, g.hFontBase, TRUE);
        SetWindowFont(g.hQuarantineBtn, g.hFontBase, TRUE);
        SetWindowFont(g.hStatus, g.hFontBase, TRUE);
        SetWindowFont(g.hStatFiles, g.hFontStatNum, TRUE);
        SetWindowFont(g.hStatThreats, g.hFontStatNum, TRUE);
        SetWindowFont(g.hStatTime, g.hFontStatNum, TRUE);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        RECT rc;
        GetWindowRect(hCtrl, &rc);
        POINT pt = { rc.left, rc.top };
        ScreenToClient(hwnd, &pt);
        if (pt.y < S(BANNER_H)) {
            SetTextColor(hdc, CLR_TEXT_ON_BANNER);
            SetBkMode(hdc, TRANSPARENT);
            static HBRUSH br = (HBRUSH)GetStockObject(NULL_BRUSH);
            return (LRESULT)br;
        }
        SetBkMode(hdc, TRANSPARENT);
        static HBRUSH br2 = (HBRUSH)GetStockObject(NULL_BRUSH);
        return (LRESULT)br2;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        drawBanner(hdc, rc.right);
        RECT rcWork = { 0, S(BANNER_H), rc.right, rc.bottom };
        HBRUSH work = CreateSolidBrush(CLR_PANEL_BG);
        FillRect(hdc, &rcWork, work);
        DeleteObject(work);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        if (dis->CtlID == IDC_LOGO) {
            drawShield(dis->hDC, dis->rcItem.left + dis->rcItem.right / 2 - S(2),
                       dis->rcItem.top + dis->rcItem.bottom / 2 - S(2), S(52));
            return TRUE;
        }
        return 0;
    }

    case WM_NOTIFY: {
        NMHDR* nm = (NMHDR*)lParam;
        if (nm->idFrom == IDC_LIST && nm->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW* cd = (NMLVCUSTOMDRAW*)lParam;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) {
                return CDRF_NOTIFYITEMDRAW;
            } else if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int idx = (int)cd->nmcd.dwItemSpec;
                if (idx >= 0 && idx < (int)g.results.size() && g.results[idx].infected) {
                    if (isSuspiciousThreat(g.results[idx].threat)) {
                        cd->clrTextBk = CLR_SUSPICIOUS;
                        cd->clrText = RGB(255, 255, 255);
                    } else {
                        cd->clrTextBk = CLR_THREAT;
                        cd->clrText = RGB(255, 255, 255);
                    }
                }
                return CDRF_NEWFONT;
            }
        }
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
            g.heuristicEnabled = (SendMessageW(g.hHeuristicCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            ListView_DeleteAllItems(g.hList);
            g.results.clear();
            g.infectedCount = 0;
            g.suspiciousCount = 0;
            SendMessageW(g.hProgress, PBM_SETPOS, 0, 0);
            EnableWindow(g.hScanBtn, FALSE);
            EnableWindow(g.hStopBtn, TRUE);
            EnableWindow(g.hQuarantineBtn, FALSE);
            setStatus(L"扫描中...");
            SetWindowTextW(g.hStatTime, L"...");
            SetWindowTextW(g.hStatThreats, L"0");

            g.scanning = true;
            g.stopRequested = false;
            g.scanStartTime = GetTickCount64();
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
        wchar_t buf[32];
        swprintf_s(buf, L"%llu", (unsigned long long)done);
        SetWindowTextW(g.hStatFiles, buf);
        return 0;
    }
    case WM_SCAN_THREAT: {
        size_t idx = (size_t)wParam;
        if (idx < g.results.size()) {
            addListItem(utf8ToWide(g.results[idx].path).c_str(),
                        utf8ToWide(g.results[idx].threat).c_str());
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
        ULONGLONG elapsed = (GetTickCount64() - g.scanStartTime) / 1000;
        wchar_t buf[32];
        swprintf_s(buf, L"%llus", (unsigned long long)elapsed);
        SetWindowTextW(g.hStatTime, buf);
        swprintf_s(buf, L"%llu", (unsigned long long)infected);
        SetWindowTextW(g.hStatThreats, buf);

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
    // 声明 Per-Monitor DPI 感知（解决高分屏模糊）—— 在创建窗口前调用
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    BOOL dpiSetOk = FALSE;
    if (hUser32) {
        typedef BOOL(WINAPI* SetProcessDpiAwarenessContextFn)(HANDLE);
        SetProcessDpiAwarenessContextFn fn = (SetProcessDpiAwarenessContextFn)GetProcAddress(
            hUser32, "SetProcessDpiAwarenessContext");
        if (fn) {
            dpiSetOk = fn((HANDLE)-4);  // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        } else {
            // 旧系统回退
            typedef BOOL(WINAPI* SetProcessDPIAwareFn)();
            SetProcessDPIAwareFn fn2 = (SetProcessDPIAwareFn)GetProcAddress(hUser32, "SetProcessDPIAware");
            if (fn2) { dpiSetOk = fn2(); }
        }
    }

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    // 创建窗口前先按主屏 DPI 初始化缩放系数（DPI 感知下窗口尺寸为物理像素）
    {
        HDC hdc = GetDC(NULL);
        if (hdc) {
            UINT dpi = GetDeviceCaps(hdc, LOGPIXELSX);
            g_scale = dpi / 96.0f;
            ReleaseDC(NULL, hdc);
        }
    }

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
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BlockAVWindow";
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassW(&wc);

    // 用 96 DPI 逻辑尺寸创建（DPI 感知下系统自动按物理像素渲染）
    HWND hwnd = CreateWindowW(L"BlockAVWindow", L"方块杀毒 BlockAV",
                              WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              S(800), S(620),
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
