#pragma once


// CMessageDlg dialog

class CMessageDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CMessageDlg)

public:
	CMessageDlg(CWnd* pParent = NULL);   // standard constructor
    CMessageDlg(POPEN_PROCESS_INFO pOpenProcessInfo);
	virtual ~CMessageDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG_MESSAGE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    virtual BOOL OnInitDialog();
    virtual BOOL PreTranslateMessage(MSG* pMsg);
    afx_msg void OnTimer(UINT_PTR nIDEvent);
    afx_msg void OnClose();
    afx_msg void OnBnClickedButtonDeny();
    afx_msg void OnBnClickedButtonAllow();
    
    void    OnOpenProcessAlert();

private:
    UINT                m_nAlertType;
    UINT                m_uIDEvent;     //Timer
    POPEN_PROCESS_INFO      m_pOpenProcess;
    

#define ALERT_OPEN_PROCESS      1
};
