#ifndef _SHADOW_H_
#define _SHADOW_H_

#include <Windows.h>

// Auto allow or deny
typedef struct _AUTO_PROGRESS {
    ULONG           ulPID;
    _AUTO_PROGRESS  *pNextNode;
    BOOL            bAllow;
    WCHAR           szImagePath[1];
} AUTO_PROGRESS, *PAUTO_PROGRESS;

#endif  /* _SHADOW_H_ */