// TipsDlg.cpp : implementation file
//

#include "stdafx.h"
#include "AvShadow.h"
#include "TipsDlg.h"
#include "afxdialogex.h"


// CTipsDlg dialog

IMPLEMENT_DYNAMIC(CTipsDlg, CDialogEx)

CTipsDlg::CTipsDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CTipsDlg::IDD, pParent)
{
    m_uIDEvent = 0;
    m_uLimitSeconds = 3;
    m_szWndTitle = _T("Avshadow Anti Virus");
    m_pCreateProcessEx = NULL;
}

CTipsDlg::CTipsDlg(PCREATE_PROCESSEX_INFO pCreateProcessExInfo, WCHAR   *szText, UINT uLimitSeconds)
    : CDialogEx(CTipsDlg::IDD)
{
    m_uIDEvent = 0;
    m_uLimitSeconds = uLimitSeconds;
    m_szWndTitle = szText;
    m_nAlertType = ALERT_CREATE_PROCESSEX;
    m_pCreateProcessEx = pCreateProcessExInfo;
}

CTipsDlg::CTipsDlg(PLOAD_DRIVER_INFO pLoadDriverInfo, WCHAR   *szText, UINT uLimitSeconds)
    : CDialogEx(CTipsDlg::IDD)
{
    m_uIDEvent = 0;
    m_uLimitSeconds = uLimitSeconds;
    m_szWndTitle = szText;
    m_nAlertType = ALERT_LOAD_DRIVER;
    m_pLoadDriver = pLoadDriverInfo;
}

CTipsDlg::~CTipsDlg()
{
}

void CTipsDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CTipsDlg, CDialogEx)
    ON_WM_TIMER()
    ON_WM_CLOSE()
    ON_BN_CLICKED(IDC_BUTTON_ALLOW, &CTipsDlg::OnBnClickedButtonAllow)
    ON_BN_CLICKED(IDC_BUTTON_DENY, &CTipsDlg::OnBnClickedButtonDeny)
END_MESSAGE_MAP()


// CTipsDlg message handlers


BOOL CTipsDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    PlaySound(NULL, AfxGetInstanceHandle(), SND_RESOURCE | SND_ASYNC);
    PlaySound(MAKEINTRESOURCE(IDR_WAVE_ALERT), AfxGetInstanceHandle(), SND_RESOURCE | SND_ASYNC);
    SetWindowText(m_szWndTitle);
    WCHAR   szCaption[16] = { 0 };
    swprintf_s(szCaption, 16, _T("Deny(%d)"), m_uLimitSeconds);
    SetDlgItemText(IDC_BUTTON_DENY, szCaption);
    GetDlgItem(IDC_STATIC_ICON)->SetWindowPos(NULL, 0, 0, 48, 48, SWP_NOZORDER | SWP_NOMOVE | SWP_SHOWWINDOW);
    switch (m_nAlertType)
    {
    case ALERT_CREATE_PROCESSEX:
        OnCreateProcessExAlert();
        break;

    case ALERT_LOAD_DRIVER:
        GetDlgItem(IDC_CHECK_REM)->ShowWindow(SW_HIDE);
        OnLoadDriverAlert();
        break;
    }
    m_uIDEvent = SetTimer(ID_TIMER, 1000, NULL);
    return TRUE;  // return TRUE unless you set the focus to a control
}


void CTipsDlg::OnTimer(UINT_PTR nIDEvent)
{
    switch (nIDEvent)
    {
    case ID_TIMER:
        WCHAR   szText[32] = { 0 };
        GetDlgItemText(IDC_BUTTON_DENY, szText, sizeof(szText) / sizeof(szText[0]));
        int     nSeconds = 0;
        swscanf_s(szText, _T("Deny(%d)"), &nSeconds);
        if (nSeconds)
        {
            wsprintf(szText, _T("Deny(%d)"), --nSeconds);
            SetDlgItemText(IDC_BUTTON_DENY, szText);
        }
        else
        {
            KillTimer(m_uIDEvent);
            m_uIDEvent = 0;
            EndDialog(RESULT_DENY); // default deny
        }
        break;
    }
    CDialogEx::OnTimer(nIDEvent);
}

void CTipsDlg::OnClose()
{
    if (m_uIDEvent)
        KillTimer(m_uIDEvent);
    CDialogEx::OnClose();
}

void CTipsDlg::OnBnClickedButtonAllow()
{
    if (BST_CHECKED == IsDlgButtonChecked(IDC_CHECK_REM))
    {
        PAUTO_PROGRESS  pLastNode = NULL;
        ULONG           ulSize     = 12 + ((wcslen(m_pCreateProcessEx->szImagePath) + 1) << 1);
        if (g_pAutoProgressListHeader)
        {
            pLastNode = g_pAutoProgressListHeader;
            while (pLastNode->pNextNode)
                pLastNode = pLastNode->pNextNode;
            // add item in list tail
            pLastNode->pNextNode = (PAUTO_PROGRESS)malloc(ulSize);
            pLastNode = pLastNode->pNextNode;
        }
        else {
            pLastNode = g_pAutoProgressListHeader = (PAUTO_PROGRESS)malloc(ulSize);
        }
        pLastNode->pNextNode = NULL;
        pLastNode->ulPID = (ULONG)m_pCreateProcessEx->ulProcessID;
        pLastNode->bAllow = TRUE;
        wcscpy_s((WCHAR*)((ULONG)pLastNode + 12), wcslen(m_pCreateProcessEx->szImagePath) + 1, m_pCreateProcessEx->szImagePath);
    }
    EndDialog(RESULT_ALLOW);
}

void CTipsDlg::OnBnClickedButtonDeny()
{
    if (BST_CHECKED == IsDlgButtonChecked(IDC_CHECK_REM))
    {
        PAUTO_PROGRESS  pLastNode = NULL;
        ULONG           ulSize     = 12 + ((wcslen(m_pCreateProcessEx->szImagePath) + 1) << 1);
        if (g_pAutoProgressListHeader)
        {
            pLastNode = g_pAutoProgressListHeader;
            while (pLastNode->pNextNode)
                pLastNode = pLastNode->pNextNode;
            // add item in list tail
            pLastNode->pNextNode = (PAUTO_PROGRESS)malloc(ulSize);
            pLastNode = pLastNode->pNextNode;
        }
        else {
            pLastNode = g_pAutoProgressListHeader = (PAUTO_PROGRESS)malloc(ulSize);
        }
        pLastNode->pNextNode = NULL;
        pLastNode->ulPID = (ULONG)m_pCreateProcessEx->ulProcessID;
        pLastNode->bAllow = FALSE;
        wcscpy_s((WCHAR*)((ULONG)pLastNode + 12), wcslen(m_pCreateProcessEx->szImagePath) + 1, m_pCreateProcessEx->szImagePath);
    }
    EndDialog(RESULT_DENY);
}

 void CTipsDlg::OnCreateProcessExAlert()
 {
     WCHAR           szTipsInfo[256] = { 0 };
     WCHAR           szProcessName[64] = { 0 };
     MultiByteToWideChar(CP_ACP, 0, m_pCreateProcessEx->szParentProcessName, strlen(m_pCreateProcessEx->szParentProcessName) + 1, szProcessName, 64);
     swprintf_s(szTipsInfo, 256, _T("PID:\t\t%d\r\nImage Name:\t%ws\r\nImage Path:\t%ws\r\nIt want to create a process:\r\n\t\t%ws"), m_pCreateProcessEx->ulProcessID, szProcessName, m_pCreateProcessEx->szImagePath, m_pCreateProcessEx->szImagePathToCreateProcess);
     SetDlgItemText(IDC_STATIC_INFO, szTipsInfo);
 }

 void CTipsDlg::OnLoadDriverAlert()
 {
     WCHAR           szTipsInfo[256] = { 0 };
     swprintf_s(szTipsInfo, _T("PID:\t\t%d\r\nImage Path:\t%ws\r\nRegistry Path:\t%ws\r\nDriver Path:\t%ws"), m_pLoadDriver->ulProcessID, m_pLoadDriver->szImagePath, m_pLoadDriver->szRegPath, m_pLoadDriver->szSysFilePath);
     SetDlgItemText(IDC_STATIC_INFO, szTipsInfo);
 }