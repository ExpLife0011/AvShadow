
// AvShadow.cpp : ����Ӧ�ó��������Ϊ��
//

#include "stdafx.h"
#include "AvShadow.h"
#include "AvShadowDlg.h"
#include "DriverService.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAvShadowApp

BEGIN_MESSAGE_MAP(CAvShadowApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CAvShadowApp ����

CAvShadowApp::CAvShadowApp()
{
	// ֧����������������
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: �ڴ˴���ӹ�����룬
	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��
}


// Ψһ��һ�� CAvShadowApp ����

CAvShadowApp theApp;


// CAvShadowApp ��ʼ��

BOOL CAvShadowApp::InitInstance()
{
	// ���һ�������� Windows XP �ϵ�Ӧ�ó����嵥ָ��Ҫ
	// ʹ�� ComCtl32.dll �汾 6 ����߰汾�����ÿ��ӻ���ʽ��
	//����Ҫ InitCommonControlsEx()�����򣬽��޷��������ڡ�
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// ��������Ϊ��������Ҫ��Ӧ�ó�����ʹ�õ�
	// �����ؼ��ࡣ
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// ���� shell ���������Է��Ի������
	// �κ� shell ����ͼ�ؼ��� shell �б���ͼ�ؼ���
	CShellManager *pShellManager = new CShellManager;
	SetRegistryKey(_T("Avshadow"));

    // ������������
    WCHAR   szSysFilePath[256];
    GetCurrentDirectory(256, szSysFilePath);
    wcscat_s(szSysFilePath, _T("\\AvShadow.sys"));
    StartDriverService(SERVICE_NAME, szSysFilePath);
    
	CAvShadowDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	// ɾ�����洴���� shell ��������
	if (pShellManager)
	{
		delete pShellManager;
	}
	// ���ڶԻ����ѹرգ����Խ����� FALSE �Ա��˳�Ӧ�ó��򣬶���������Ӧ�ó������Ϣ�á�
	return FALSE;
}

