// MessageDlg.cpp : implementation file
//

#include "stdafx.h"
#include "AvShadow.h"
#include "MessageDlg.h"
#include "afxdialogex.h"
#include "AvShadowDlg.h"


// CMessageDlg dialog

IMPLEMENT_DYNAMIC(CMessageDlg, CDialogEx)

CMessageDlg::CMessageDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CMessageDlg::IDD, pParent)
{
    m_uIDEvent = 0;
    m_pOpenProcess = NULL;
}

CMessageDlg::CMessageDlg(POPEN_PROCESS_INFO pOpenProcessInfo)
    : CDialogEx(CMessageDlg::IDD)
{
    m_uIDEvent = 0;
    m_nAlertType = ALERT_OPEN_PROCESS;
    m_pOpenProcess = pOpenProcessInfo;
}

CMessageDlg::~CMessageDlg()
{
}

void CMessageDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CMessageDlg, CDialogEx)
    ON_WM_TIMER()
    ON_WM_CLOSE()
    ON_BN_CLICKED(IDC_BUTTON_DENY, &CMessageDlg::OnBnClickedButtonDeny)
    ON_BN_CLICKED(IDC_BUTTON_ALLOW, &CMessageDlg::OnBnClickedButtonAllow)
END_MESSAGE_MAP()


// CMessageDlg message handlers


BOOL CMessageDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    PlaySound(MAKEINTRESOURCE(NULL), AfxGetInstanceHandle(), SND_RESOURCE | SND_ASYNC);
    PlaySound(MAKEINTRESOURCE(IDR_WAVE_ALERT), AfxGetInstanceHandle(), SND_RESOURCE | SND_ASYNC);
    switch (m_nAlertType)
    {
    case ALERT_OPEN_PROCESS:
        OnOpenProcessAlert();
        break;
    }
    GetDlgItem(IDC_STATIC_ICON)->SetWindowPos(NULL, 0, 0, 48, 48, SWP_NOZORDER | SWP_NOMOVE | SWP_SHOWWINDOW);

    CRect rectWorkArea;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &rectWorkArea, SPIF_SENDCHANGE);   
    CRect rectDlg;
    GetWindowRect(&rectDlg);
    ::SetWindowPos(GetSafeHwnd(), HWND_BOTTOM, rectWorkArea.right - rectDlg.Width(), rectWorkArea.bottom - rectDlg.Height(), rectDlg.Width(), rectDlg.Height(), SWP_NOZORDER);
    AnimateWindow(1000, AW_VER_NEGATIVE | AW_SLIDE);
    m_uIDEvent = SetTimer(ID_TIMER, 1000, NULL);
        
    return TRUE;  // return TRUE unless you set the focus to a control
}

void CMessageDlg::OnTimer(UINT_PTR nIDEvent)
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
            EndDialog(RESULT_DENY); // д╛хон╙╬э╬Ь
        }
        break;
    }
    CDialogEx::OnTimer(nIDEvent);
}

void CMessageDlg::OnClose()
{
    if (m_uIDEvent)
        KillTimer(m_uIDEvent);
    CDialogEx::OnClose();
}

BOOL CMessageDlg::PreTranslateMessage(MSG* pMsg)
{
    if (WM_KEYDOWN == pMsg->message && VK_RETURN == pMsg->wParam)
        return TRUE;
    return CDialogEx::PreTranslateMessage(pMsg);
}

void CMessageDlg::OnBnClickedButtonDeny()
{
    if (BST_CHECKED == IsDlgButtonChecked(IDC_CHECK_REM))
    {
        PAUTO_PROGRESS  pLastNode = NULL;
        ULONG           ulSize     = 12 + ((wcslen(m_pOpenProcess->szImagePath) + 1) << 1);
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
        pLastNode->ulPID = (ULONG)m_pOpenProcess->ulProcessID;
        pLastNode->bAllow = FALSE;
        wcscpy_s((WCHAR*)((ULONG)pLastNode + 12), wcslen(m_pOpenProcess->szImagePath) + 1, m_pOpenProcess->szImagePath);
    }
    EndDialog(RESULT_DENY);
}

void CMessageDlg::OnBnClickedButtonAllow()
{
    if (BST_CHECKED == IsDlgButtonChecked(IDC_CHECK_REM))
    {
        PAUTO_PROGRESS  pLastNode = NULL;
        ULONG           ulSize     = 12 + ((wcslen(m_pOpenProcess->szImagePath) + 1) << 1);
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
        pLastNode->ulPID = (ULONG)m_pOpenProcess->ulProcessID;
        pLastNode->bAllow = TRUE;
        wcscpy_s((WCHAR*)((ULONG)pLastNode + 12), wcslen(m_pOpenProcess->szImagePath) + 1, m_pOpenProcess->szImagePath);
    }
    EndDialog(RESULT_ALLOW);
}

void CMessageDlg::OnOpenProcessAlert()
{
    WCHAR           szTipsInfo[256] = { 0 };
    WCHAR           szProcessName[64] = { 0 };
    WCHAR           szTargetProcessName[64] = { 0 };
    CAvShadowDlg::GetProcessNameById((DWORD)m_pOpenProcess->ulTargetProcessID, szTargetProcessName, 64);
    MultiByteToWideChar(CP_ACP, 0, m_pOpenProcess->szProcessName, strlen(m_pOpenProcess->szProcessName) + 1, szProcessName, 64);
    swprintf_s(szTipsInfo, 256, _T("PID:%d\r\nImage Name:%ws\r\nImage Path:\r\n%ws\r\nTarget PID:%d\r\nTarget Image Name:%ws\r\nIt is calling NtOpenProces.\r\nYou can choose allow or deny."), m_pOpenProcess->ulProcessID, szProcessName, m_pOpenProcess->szImagePath, m_pOpenProcess->ulTargetProcessID, szTargetProcessName);
    SetDlgItemText(IDC_STATIC_INFO, szTipsInfo);
}