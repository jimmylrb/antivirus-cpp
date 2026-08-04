// gui.cpp — 方块杀毒 BlockAV 图形界面 v2（现代杀软风格，Unicode）
// 深色横幅 + 品牌渐变 + 威胁分级着色 + 扫描统计 + 启发式检测

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
// 深色横幅渐变（蓝 -> 紫）
#define CLR_BANNER_1  RGB(0x2D, 0x9C, 0xDB)   // 亮蓝
#define CLR_BANNER_2  RGB(0x5B, 0x4F, 0xCF)   // 靛蓝
#define CLR_BANNER_3  RGB(0x8B, 0x5C, 0xF6)   // 紫
#define CLR_ACCENT    RGB(0x00, 0xC8, 0xFF)   // 强调青
#define CLR_TEXT_ON_BANNER RGB(255, 255, 255)
#define CLR_TEXT_DIM  RGB(0xB0, 0xC4, 0xDE)
#define CLR_THREAT    RGB(0xFF, 0x6B, 0x6B)   // 红 - 已知威胁
#define CLR_SUSPICIOUS RGB(0xFF, 0xA9, 0x4D)  // 橙 - 可疑
#define CLR_CLEAN     RGB(0x51, 0xCF, 0x66)   // 绿 - 干净
#define CLR_PANEL_BG  RGB(0xF5, 0xF7, 0xFA)   // 浅色工作区
#define CLR_BAR       RGB(0x00, 0xB8, 0xE6)   // 进度条蓝

// 横幅布局
#define BANNER_H  100
#define TOP_OFF   (BANNER_H + 12)

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

// 在横幅上绘制盾牌图标（矢量）
static void drawShield(HDC hdc, int x, int y, int size) {
    // 盾牌外轮廓
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
    HBRUSH br = CreateSolidBrush(RGB(255, 255, 255));
    HGDIOBJ oldPen = SelectObject(hdc, pen);
    HGDIOBJ oldBr = SelectObject(hdc, br);
    // 盾形路径
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
    // 盾牌内对勾（用强调色）
    HPEN checkPen = CreatePen(PS_SOLID, 3, CLR_BANNER_1);
    SelectObject(hdc, checkPen);
    MoveToEx(hdc, x - size / 4, y, NULL);
    LineTo(hdc, x - size / 10, y + size / 5);
    LineTo(hdc, x + size / 4, y - size / 5);
    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldBr);
    DeleteObject(pen); DeleteObject(br); DeleteObject(checkPen);
}

// 绘制横幅渐变背景
static void drawBanner(HDC hdc, int width) {
    // 三色渐变（蓝 -> 靛 -> 紫）
    for (int y = 0; y < BANNER_H; ++y) {
        double t = (double)y / BANNER_H;
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

// 判断威胁类型（用于着色）：true = 启发式可疑，false = 已知威胁
static bool isSuspiciousThreat(const std::string& threat) {
    return threat.find("[启发式]") != std::string::npos;
}

// ---------- 扫描线程 ----------

static void scanThreadFunc(const std::string& path) {
    // 统计文件总数
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

        // 字体：微软雅黑
        g.hFontTitle = CreateFontW(26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontBig = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontBase = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontStat = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g.hFontStatNum = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");

        // 标题 + 副标题（横幅上的文字控件）
        g.hLogo = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
                                20, 14, 72, 72, hwnd, (HMENU)IDC_LOGO, hInst, NULL);
        CreateWindowW(L"STATIC", L"方块杀毒 BlockAV", WS_CHILD | WS_VISIBLE,
                      100, 20, 300, 34, hwnd, NULL, hInst, NULL);
        CreateWindowW(L"STATIC", L"C++ 杀毒引擎 · ClamAV 病毒库 · 启发式分析 · 实时防护",
                      WS_CHILD | WS_VISIBLE, 100, 56, 420, 22, hwnd, NULL, hInst, NULL);

        // 统计数字（横幅右侧三卡片）
        g.hStatFiles = CreateWindowW(L"STATIC", L"0", WS_CHILD | WS_VISIBLE,
                                     520, 18, 70, 34, hwnd, (HMENU)IDC_STAT_FILES, hInst, NULL);
        CreateWindowW(L"STATIC", L"已扫描", WS_CHILD | WS_VISIBLE, 520, 56, 70, 20, hwnd, NULL, hInst, NULL);
        g.hStatThreats = CreateWindowW(L"STATIC", L"0", WS_CHILD | WS_VISIBLE,
                                       615, 18, 70, 34, hwnd, (HMENU)IDC_STAT_THREATS, hInst, NULL);
        CreateWindowW(L"STATIC", L"威胁", WS_CHILD | WS_VISIBLE, 615, 56, 70, 20, hwnd, NULL, hInst, NULL);
        g.hStatTime = CreateWindowW(L"STATIC", L"0s", WS_CHILD | WS_VISIBLE,
                                    710, 18, 70, 34, hwnd, (HMENU)IDC_STAT_TIME, hInst, NULL);
        CreateWindowW(L"STATIC", L"用时", WS_CHILD | WS_VISIBLE, 710, 56, 70, 20, hwnd, NULL, hInst, NULL);

        // 工作区控件
        CreateWindowW(L"STATIC", L"扫描目录:", WS_CHILD | WS_VISIBLE,
                      20, TOP_OFF, 70, 24, hwnd, NULL, hInst, NULL);
        g.hEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                90, TOP_OFF - 2, 380, 28, hwnd, (HMENU)IDC_PATH_EDIT, hInst, NULL);
        g.hScanBtn = CreateWindowW(L"BUTTON", L"开始扫描", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   480, TOP_OFF - 2, 100, 28, hwnd, (HMENU)IDC_SCAN_BTN, hInst, NULL);
        g.hStopBtn = CreateWindowW(L"BUTTON", L"停止", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                   585, TOP_OFF - 2, 60, 28, hwnd, (HMENU)IDC_STOP_BTN, hInst, NULL);
        g.hBrowse = CreateWindowW(L"BUTTON", L"浏览...", WS_CHILD | WS_VISIBLE,
                                  650, TOP_OFF - 2, 70, 28, hwnd, (HMENU)IDC_BROWSE, hInst, NULL);

        g.hHeuristicCheck = CreateWindowW(L"BUTTON", L"启用启发式检测（识别未知可疑文件）",
                                          WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                          20, TOP_OFF + 34, 330, 22, hwnd, (HMENU)IDC_HEURISTIC_CHECK, hInst, NULL);
        SendMessageW(g.hHeuristicCheck, BM_SETCHECK, BST_CHECKED, 0);

        g.hProgress = CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
                                    20, TOP_OFF + 62, 700, 12, hwnd, (HMENU)IDC_PROGRESS, hInst, NULL);
        SendMessageW(g.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 10000));
        SendMessageW(g.hProgress, PBM_SETBARCOLOR, 0, (LPARAM)CLR_BAR);
        SendMessageW(g.hProgress, PBM_SETBKCOLOR, 0, (LPARAM)RGB(0xE2, 0xE8, 0xF0));

        // 结果列表
        g.hList = CreateWindowW(WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER |
                                LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                20, TOP_OFF + 84, 700, 330, hwnd, (HMENU)IDC_LIST, hInst, NULL);
        ListView_SetExtendedListViewStyle(g.hList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
        LVCOLUMNW col;
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 460;
        col.pszText = (LPWSTR)L"文件";
        ListView_InsertColumn(g.hList, 0, &col);
        col.cx = 230;
        col.pszText = (LPWSTR)L"检测结果";
        ListView_InsertColumn(g.hList, 1, &col);

        g.hQuarantineBtn = CreateWindowW(L"BUTTON", L"隔离选中", WS_CHILD | WS_VISIBLE | WS_DISABLED,
                                         20, TOP_OFF + 424, 100, 30, hwnd, (HMENU)IDC_QUARANTINE_BTN, hInst, NULL);
        g.hStatus = CreateWindowW(L"STATIC", L"就绪 - 请选择要扫描的目录", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
                                  130, TOP_OFF + 424, 590, 30, hwnd, (HMENU)IDC_STATUS, hInst, NULL);

        // 应用字体
        for (HWND h = GetWindow(hwnd, GW_CHILD); h; h = GetWindow(h, GW_HWNDNEXT)) {
            int id = GetDlgCtrlID(h);
            if (id == IDC_LOGO) continue;
            if (id == IDC_STAT_FILES || id == IDC_STAT_THREATS || id == IDC_STAT_TIME)
                SetWindowFont(h, g.hFontStatNum, TRUE);
            else if (id == 0 && GetWindowLongPtrW(h, GWLP_ID) == 0 && h != hwnd) {
                // 标题/副标题（父窗口直接子控件，无 ID）
                RECT rc; GetWindowRect(h, &rc);
                if ((rc.bottom - rc.top) >= 30) SetWindowFont(h, g.hFontTitle, TRUE);
                else SetWindowFont(h, g.hFontStat, TRUE);
            } else {
                SetWindowFont(h, g.hFontBase, TRUE);
            }
        }
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        // 横幅区域内的文字：白色 + 透明背景
        RECT rc;
        GetWindowRect(hCtrl, &rc);
        POINT pt = { rc.left, rc.top };
        ScreenToClient(hwnd, &pt);
        int id = GetDlgCtrlID(hCtrl);
        if (pt.y < BANNER_H) {
            SetTextColor(hdc, CLR_TEXT_ON_BANNER);
            if (id == IDC_STAT_FILES || id == IDC_STAT_THREATS || id == IDC_STAT_TIME)
                SetTextColor(hdc, CLR_TEXT_ON_BANNER);
            SetBkMode(hdc, TRANSPARENT);
            static HBRUSH br = (HBRUSH)GetStockObject(NULL_BRUSH);
            return (LRESULT)br;
        }
        // 工作区：正常颜色
        SetBkMode(hdc, TRANSPARENT);
        static HBRUSH br2 = (HBRUSH)GetStockObject(NULL_BRUSH);
        return (LRESULT)br2;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        // 横幅
        drawBanner(hdc, 780);
        // 盾牌
        drawShield(hdc, 56, 50, 44);
        // 工作区背景
        RECT rcWork = { 0, BANNER_H, 780, 620 };
        HBRUSH work = CreateSolidBrush(CLR_PANEL_BG);
        FillRect(hdc, &rcWork, work);
        DeleteObject(work);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        if (dis->CtlID == IDC_LOGO) {
            drawShield(dis->hDC, dis->rcItem.left + dis->rcItem.right / 2 - 2,
                       dis->rcItem.top + dis->rcItem.bottom / 2 - 2, 52);
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
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BlockAVWindow";
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(L"BlockAVWindow", L"方块杀毒 BlockAV",
                              WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                              CW_USEDEFAULT, CW_USEDEFAULT, 800, 620,
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
