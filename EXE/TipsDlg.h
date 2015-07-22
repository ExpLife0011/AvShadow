#pragma once


// CTipsDlg dialog

class CTipsDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CTipsDlg)

public:
	CTipsDlg(CWnd* pParent = NULL);   // standard constructor
    CTipsDlg(PCREATE_PROCESSEX_INFO pCreateProcessExInfo, WCHAR *szText, UINT uLimitSeconds = 3);
    CTipsDlg(PLOAD_DRIVER_INFO pLoadDriverInfo, WCHAR   *szText, UINT uLimitSeconds = 3);
	virtual ~CTipsDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG_TIP };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    virtual BOOL OnInitDialog();
    afx_msg void OnTimer(UINT_PTR nIDEvent);
    afx_msg void OnClose();
    afx_msg void OnBnClickedButtonAllow();
    afx_msg void OnBnClickedButtonDeny();

private:
    WCHAR               *m_szWndTitle;
    UINT                m_nAlertType;
    UINT                m_uIDEvent;     //Timer
    UINT                m_uLimitSeconds;
    PCREATE_PROCESSEX_INFO  m_pCreateProcessEx;
    PLOAD_DRIVER_INFO       m_pLoadDriver;

private:
    void    OnCreateProcessExAlert();
    void    OnLoadDriverAlert();

#define ALERT_CREATE_PROCESSEX      1
#define ALERT_LOAD_DRIVER           2
};
