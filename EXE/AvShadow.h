
// AvShadow.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CAvShadowApp:
// �йش����ʵ�֣������ AvShadow.cpp
//

class CAvShadowApp : public CWinApp
{
public:
	CAvShadowApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CAvShadowApp theApp;