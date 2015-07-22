
// AvShadowDlg.h : 头文件
//

#pragma once


// CAvShadowDlg 对话框
class CAvShadowDlg : public CDialogEx
{
// 构造
public:
	CAvShadowDlg(CWnd* pParent = NULL);	// 标准构造函数
    ~CAvShadowDlg();

// 对话框数据
	enum { IDD = IDD_AVSHADOW_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
    virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
    afx_msg void OnClose();
    afx_msg LRESULT OnTray(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()

public:
    static  DWORD WINAPI ThreadProcOpenProcess(LPVOID lpParameter);
    static  DWORD WINAPI ThreadProcCreateProcessEx(LPVOID lpParameter);
    static  DWORD WINAPI ThreadProcLoadDriver(LPVOID lpParameter);
    static  BOOL    GetProcessNameById(IN DWORD dwPID, OUT WCHAR *szProcessName, IN size_t numberOfElements);
    static  void    InitWhiteList();   
    DWORD   OnOpenProcess();
    DWORD   OnCreateProcessEx();
    DWORD   OnLoadDriver();
    void    StartTray();

private:
    HANDLE          m_hDevice;
    HANDLE          m_hEvent;
    HANDLE          m_hThreadOpenProcess;
    HANDLE          m_hThreadCreateProcessEx;
    HANDLE          m_hThreadLoadDriver;
    DWORD           m_dwAvPID;

    NOTIFYICONDATA  m_NotifyiconData;
    DWORD           m_dwBytesReturned;
    HANDLE          *m_phEvent;
    CMenu           m_TrayMenu;

#define  TRAY_MESSAGE   WM_USER + 1
public:
    afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
};
