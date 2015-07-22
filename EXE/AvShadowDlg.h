
// AvShadowDlg.h : ͷ�ļ�
//

#pragma once


// CAvShadowDlg �Ի���
class CAvShadowDlg : public CDialogEx
{
// ����
public:
	CAvShadowDlg(CWnd* pParent = NULL);	// ��׼���캯��
    ~CAvShadowDlg();

// �Ի�������
	enum { IDD = IDD_AVSHADOW_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
