
// AvShadowDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "AvShadow.h"
#include "AvShadowDlg.h"
#include "afxdialogex.h"
#include "MessageDlg.h"
#include "TipsDlg.h"
#include "AvShadowIoCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAvShadowDlg 对话框




CAvShadowDlg::CAvShadowDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CAvShadowDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
    m_hDevice = INVALID_HANDLE_VALUE;
    m_hEvent = NULL;
    m_dwBytesReturned = 0;
    m_phEvent = NULL;
}

CAvShadowDlg::~CAvShadowDlg()
{

}

void CAvShadowDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAvShadowDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_WM_CLOSE()
    ON_MESSAGE(TRAY_MESSAGE, OnTray)
    ON_WM_SYSCOMMAND()
END_MESSAGE_MAP()


// CAvShadowDlg 消息处理程序

BOOL CAvShadowDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

    StartTray();
    m_TrayMenu.LoadMenu(IDR_MENU_TRAY);
    InitWhiteList();
    m_hDevice = CreateFile(_T("\\\\.\\Avshadow"), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    m_hEvent  = CreateEvent(NULL, TRUE, TRUE, NULL);
    m_dwAvPID = GetCurrentProcessId();
    
    // Create shared event object, then send them to the driver
    m_phEvent = (HANDLE*)malloc(sizeof(HANDLE) * EVENT_SHARE_NUM);
    RtlZeroMemory(m_phEvent, sizeof(HANDLE) * EVENT_SHARE_NUM);
    for (int i = 0; i < EVENT_SHARE_NUM; i++)
    {
        if (!(m_phEvent[i] = CreateEvent(NULL, FALSE, FALSE, NULL))) {
            MessageBox(_T("CreateEvent fails"), _T("Shadow"), MB_ICONERROR);
        }
    }
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_INIT, &m_dwAvPID, sizeof(DWORD), NULL, 0, &m_dwBytesReturned, NULL);
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_SET_EVENTHANDLE, m_phEvent, sizeof(HANDLE) * EVENT_SHARE_NUM, NULL, 0, &m_dwBytesReturned, NULL);
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_INIT_WHITELIST, g_pWhiteList, sizeof(WHITE_LIST) + g_pWhiteList->ulStringSize - 4, NULL, 0, &m_dwBytesReturned, NULL);
    //DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_START_OPENPROCESS, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_START_CREATEPROCESSEX, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);
    //DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_START_LOADDRIVER, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);
    //DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_START_QUERYSYSINFO, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);

    // TODO: free(g_pWhiteList);
    m_hThreadOpenProcess = CreateThread(NULL, 0, ThreadProcOpenProcess, this, 0, NULL);
    m_hThreadCreateProcessEx = CreateThread(NULL, 0, ThreadProcCreateProcessEx, this, 0, NULL);
    m_hThreadLoadDriver = CreateThread(NULL, 0, ThreadProcLoadDriver, this, 0, NULL);
	return TRUE;
}

// 如果向对话框添加最小化按钮，则需要下面的代码
// 来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
// 这将由框架自动完成。

void CAvShadowDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAvShadowDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

DWORD WINAPI CAvShadowDlg::ThreadProcOpenProcess(LPVOID lpParameter)
{
    return ((CAvShadowDlg*)lpParameter)->OnOpenProcess();
}

DWORD  CAvShadowDlg::OnOpenProcess()
{
    while (TRUE)
    {
        DWORD           dwBytesReturned = 0;
        BOOL            bGoonProgress = TRUE;
        OPEN_PROCESS_INFO    OpenProcess = { PacketOpenProcess, 0 };
        if (WAIT_OBJECT_0 == WaitForSingleObject(m_phEvent[EVENT_INDEX_OPENPROCESS], INFINITE))
        {
            DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_GET_OPENPROCESS, NULL, 0, &OpenProcess, sizeof(OPEN_PROCESS_INFO), &dwBytesReturned, NULL);
            // Does this process in the white list?
            PAUTO_PROGRESS  pNextNode = g_pAutoProgressListHeader;
            while (pNextNode)
            {
                if (!_wcsicmp(pNextNode->szImagePath, OpenProcess.szImagePath))
                {
                    OpenProcess.bAllowed = pNextNode->bAllow;
                    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_SET_OPENPROCESS, &OpenProcess.bAllowed, sizeof(BOOLEAN), NULL, 0, &dwBytesReturned, NULL);
                    bGoonProgress = FALSE;
                    break;
                }
                pNextNode = pNextNode->pNextNode;
            }
            if (bGoonProgress)
            {
                CMessageDlg     msgdlg(&OpenProcess);
                OpenProcess.bAllowed = RESULT_ALLOW == msgdlg.DoModal();
                DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_SET_OPENPROCESS, &OpenProcess.bAllowed, sizeof(BOOLEAN), NULL, 0, &dwBytesReturned, NULL);
            }           
        }
    }
    return 0;     
}

DWORD WINAPI CAvShadowDlg::ThreadProcLoadDriver(LPVOID lpParameter)
{
    return ((CAvShadowDlg*)lpParameter)->OnLoadDriver();
}

DWORD  CAvShadowDlg::OnLoadDriver()
{
    while (TRUE)
    {
        DWORD               dwBytesReturned = 0;
        LOAD_DRIVER_INFO    LoadDriverInfo = { 0 };
        if (WAIT_OBJECT_0 == WaitForSingleObject(m_phEvent[EVENT_INDEX_LOADDRIVER], INFINITE))
        {
            DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_GET_LOADDRIVER, NULL, 0, &LoadDriverInfo, sizeof(LOAD_DRIVER_INFO), &dwBytesReturned, NULL);
            CTipsDlg     tipsdlg(&LoadDriverInfo, _T("Driver load alert - Shadow"), 5);
            LoadDriverInfo.bAllowed = RESULT_ALLOW == tipsdlg.DoModal();
            DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_SET_LOADDRIVER, &LoadDriverInfo.bAllowed, sizeof(BOOLEAN), NULL, 0, &dwBytesReturned, NULL);          
        }
    }
    return 0;
}


DWORD WINAPI CAvShadowDlg::ThreadProcCreateProcessEx(LPVOID lpParameter)
{
    return ((CAvShadowDlg*)lpParameter)->OnCreateProcessEx();
}

DWORD  CAvShadowDlg::OnCreateProcessEx()
{
    while (TRUE)
    {
        DWORD           dwBytesReturned = 0;
        BOOL            bGoonProgress = TRUE;
        CREATE_PROCESSEX_INFO    CreateProcessExInfo = { 0 };
        if (WAIT_OBJECT_0 == WaitForSingleObject(m_phEvent[EVENT_INDEX_CREATEPROCESSEX], INFINITE))
        {
            DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_GET_CREATEPROCESSEX, NULL, 0, &CreateProcessExInfo, sizeof(CREATE_PROCESSEX_INFO), &dwBytesReturned, NULL);
            // Does this process in the white list?
            PAUTO_PROGRESS  pNextNode = g_pAutoProgressListHeader;
            while (pNextNode)
            {
                if (!_wcsicmp(pNextNode->szImagePath, CreateProcessExInfo.szImagePath))
                {
                    CreateProcessExInfo.bAllowed = pNextNode->bAllow;
                    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_SET_CREATEPROCESSEX, &CreateProcessExInfo.bAllowed, sizeof(BOOLEAN), NULL, 0, &dwBytesReturned, NULL);
                    bGoonProgress = FALSE;
                    break;
                }
                pNextNode = pNextNode->pNextNode;
            }
            if (bGoonProgress)
            {
                CTipsDlg     tipsdlg(&CreateProcessExInfo, _T("Process create alert - Shadow"), 5);
                CreateProcessExInfo.bAllowed = RESULT_ALLOW == tipsdlg.DoModal();
                DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_SET_CREATEPROCESSEX, &CreateProcessExInfo.bAllowed, sizeof(BOOLEAN), NULL, 0, &dwBytesReturned, NULL);
            }           
        }
    }
    return 0;
}

void CAvShadowDlg::OnClose()
{
    // pause monitor
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_PAUSE_OPENPROCESS, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_PAUSE_CREATEPROCESSEX, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);
    DeviceIoControl(m_hDevice, IOCTL_AVSHADOW_PAUSE_LOADDRIVER, NULL, 0, NULL, 0, &m_dwBytesReturned, NULL);

    if (m_hEvent)
    {
        ResetEvent(m_hEvent);
        Sleep(150);
        CloseHandle(m_hEvent);
    }
    if (m_hDevice != INVALID_HANDLE_VALUE)
        CloseHandle(m_hDevice);
    Shell_NotifyIcon(NIM_DELETE, &m_NotifyiconData);
    CDialogEx::OnClose();
}

void CAvShadowDlg::StartTray()
{
    RtlZeroMemory(&m_NotifyiconData, sizeof(NOTIFYICONDATA));
    m_NotifyiconData.cbSize = sizeof(NOTIFYICONDATA);
    m_NotifyiconData.hWnd = GetSafeHwnd();
    m_NotifyiconData.uID = ID_TRAY;
    m_NotifyiconData.hIcon = AfxGetApp()->LoadIconW(IDR_MAINFRAME);
    wcscpy_s(m_NotifyiconData.szTip, _T("Avshadow - Anti Virus Personal\r\nPowered by lazy_cat"));
    m_NotifyiconData.uCallbackMessage = TRAY_MESSAGE;
    m_NotifyiconData.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    Shell_NotifyIcon(NIM_ADD, &m_NotifyiconData);
}

BOOL CAvShadowDlg::PreTranslateMessage(MSG* pMsg)
{
    if (WM_KEYDOWN == pMsg->message && (VK_RETURN == pMsg->wParam || VK_ESCAPE == pMsg->wParam))
        return TRUE;
    return CDialogEx::PreTranslateMessage(pMsg);
}

BOOL CAvShadowDlg::GetProcessNameById(IN DWORD dwPID, OUT WCHAR *szProcessName, IN size_t numberOfElements)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);
    BOOL bNext = Process32First(hSnapshot, &pe32);
    while(bNext)
    {
        if(dwPID == pe32.th32ProcessID)
        {
            CloseHandle(hSnapshot);
            wcscpy_s(szProcessName, numberOfElements, pe32.szExeFile);
            return TRUE;
        }
        bNext = Process32Next(hSnapshot, &pe32);
    }
    CloseHandle(hSnapshot);
    return FALSE;
}

void CAvShadowDlg::InitWhiteList()
{
    WHITE_LIST  WhiteList;
    WCHAR   *szOmitItem[] = {
        _T("C:\\WINDOWS\\system32\\*"),
        _T("C:\\WINDOWS\\explorer.exe")
    };
    RtlZeroMemory(&WhiteList, sizeof(WHITE_LIST));
    WhiteList.ulStringCount = sizeof(szOmitItem) / sizeof(szOmitItem[0]);
    for (unsigned int i = 0; i < WhiteList.ulStringCount; i++)
    {
        WhiteList.ulStringSize += ((wcslen(szOmitItem[i]) + 1) << 1);
    }
    g_pWhiteList = (PWHITE_LIST)malloc(sizeof(WHITE_LIST) + WhiteList.ulStringSize - 4);
    g_pWhiteList->ulStringCount = WhiteList.ulStringCount;
    g_pWhiteList->ulStringSize = WhiteList.ulStringSize;

    WCHAR   *pStart = (WCHAR*)((ULONG)g_pWhiteList + sizeof(WHITE_LIST) - 4);
    RtlZeroMemory(pStart, WhiteList.ulStringSize);
    for (unsigned int i = 0; i < WhiteList.ulStringCount; i++)
    {
        RtlCopyMemory(pStart, szOmitItem[i], (wcslen(szOmitItem[i]) + 1) << 1);
        pStart += wcslen(szOmitItem[i]) + 1;
    }
}

LRESULT CAvShadowDlg::OnTray(WPARAM wParam, LPARAM lParam)
{
    POINT   pt;
    CMenu   *tray_menu = m_TrayMenu.GetSubMenu(0);

    switch (LOWORD(lParam))
    {
    case WM_RBUTTONDOWN:
        SetForegroundWindow();
        GetCursorPos(&pt);
        tray_menu->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, this);
        break;
        
    case WM_LBUTTONDBLCLK:
        ShowWindow(SW_SHOW);
        ShowWindow(SW_RESTORE);
        break;
    }
    return 0;
}

void CAvShadowDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
    switch (nID)
    {
    case SC_MINIMIZE:
    case SC_CLOSE:
        ShowWindow(SW_HIDE);
        break;
    default:
        CDialogEx::OnSysCommand(nID, lParam);
    }
}
