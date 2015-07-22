#include <Windows.h>
#include <tchar.h>
#include "AvshadowTray.h"
#include "resource.h"

NOTIFYICONDATA  NotifyiconData;
HMENU           hMenu;

int CALLBACK WinMain(
    __in  HINSTANCE hInstance,
    __in  HINSTANCE hPrevInstance,
    __in  LPSTR lpCmdLine,
    __in  int nCmdShow
    )
{
    WNDCLASS    wndclass;;
    RtlZeroMemory(&wndclass, sizeof(WNDCLASS));
    wndclass.style = CS_HREDRAW | CS_VREDRAW; 
    wndclass.lpfnWndProc = (WNDPROC) MainWndProc; 
    wndclass.cbClsExtra = 0; 
    wndclass.cbWndExtra = 0; 
    wndclass.hInstance = hInstance; 
    wndclass.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON_TRAY)); 
    wndclass.hCursor = LoadCursor(NULL, IDC_ARROW); 
    wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);  
    wndclass.lpszClassName = WNDCLASS_NAME; 
    if (!RegisterClass(&wndclass)) {
        return 0;
    }
    HWND    hWnd = CreateWindow(WNDCLASS_NAME, _T("AvShadow"), WS_OVERLAPPEDWINDOW, 0, 0, 800, 600, NULL, NULL, hInstance, NULL);

    RtlZeroMemory(&NotifyiconData, sizeof(NOTIFYICONDATA));
    NotifyiconData.cbSize = sizeof(NOTIFYICONDATA);
    NotifyiconData.hWnd = hWnd;
    NotifyiconData.uID = ID_TRAY;
    NotifyiconData.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON_TRAY));
    wcscpy_s(NotifyiconData.szTip, _T("Avshadow - Anti Virus Personal\r\nPowered by lazy_cat"));
    NotifyiconData.uCallbackMessage = TRAY_MESSAGE;
    NotifyiconData.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    Shell_NotifyIcon(NIM_ADD, &NotifyiconData);

    hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDR_MENU_TRAY));

    MSG     msg;
    while (GetMessage(&msg, NULL, NULL, NULL))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return  msg.wParam;
}

LRESULT CALLBACK MainWndProc(
    HWND    hwnd,
    UINT    uMsg,
    WPARAM  wParam,  
    LPARAM  lParam
    )
{ 
    switch (uMsg) 
    {
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAYMENU_AVSHADOWGUARDENABLE:
            break;

        case ID_TRAYMENU_STARTAVSHADOW:
            break;

        case ID_TRAYMENU_CONFIGUREAVSHADOW:
            break;

        case ID_TRAYMENU_HELP:
            break;

        case ID_TRAYMENU_ABOUTAVSHADOW:
            break;

        case ID_TRAYMENU_ACCESSAVSHADOWWEB:
            break;
        }
        break;

    case WM_CLOSE:
        DestroyMenu(hMenu);
        Shell_NotifyIcon(NIM_DELETE, &NotifyiconData);
        PostQuitMessage(0);
        break;

    case TRAY_MESSAGE:
        switch (LOWORD(lParam))
        {
        case WM_RBUTTONDOWN:
            POINT   pt;
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(GetSubMenu(hMenu, 0), TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            break;
        }
        break;

    default: 
        return DefWindowProc(hwnd, uMsg, wParam, lParam); 
    } 
    return 0; 
}
