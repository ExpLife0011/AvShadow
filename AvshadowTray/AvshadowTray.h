#define  WNDCLASS_NAME  _T("AvshadowTray")
#define  TRAY_MESSAGE   WM_USER + 1
#define  ID_TRAY        'AVer'

LRESULT CALLBACK MainWndProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,  
    LPARAM lParam
    );