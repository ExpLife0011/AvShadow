/*++

Copyright (c) 2009-2011  lazycat studio

Module Name:

    Kernel32.c

Abstract:

Author:

    lazy_cat

Environment:

    Kernel mode only

Revision History:

--*/

#include <ntddk.h>
#include "Kernel32.h"

LPVOID
ShadowGetProcAddress(
    IN  HMODULE hModule,
    IN  CHAR    *lpFunctionName
    )
/*++

Routine Description:

    Search the export table,get the target function address

Arguments:

    hModule: return from ShadowLoadLibrary
    lpFunctionName: The function or variable name,ANSI

Return Value:

    If the function fails, the return value is NULL

--*/
{
    PIMAGE_DOS_HEADER       pDosHeader;
    PIMAGE_OPTIONAL_HEADER  pOptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    PLIBRARY_INFO           pLibraryInfo = (PLIBRARY_INFO)hModule;
    unsigned    int         i;
    pDosHeader = pLibraryInfo->pBaseAddress;
    pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(((ULONG)pLibraryInfo->pBaseAddress + pDosHeader->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG)pLibraryInfo->pBaseAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    for (i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        if (!strcmp(lpFunctionName, (CHAR*)pLibraryInfo->pBaseAddress + ((ULONG*)((ULONG)pLibraryInfo->pBaseAddress + pExportDirectory->AddressOfNames))[i]))
            return (LPVOID)(((ULONG*)((ULONG)pLibraryInfo->pBaseAddress + pExportDirectory->AddressOfFunctions))[i] + (ULONG)pLibraryInfo->pBaseAddress);
    }
    return NULL;
}

HANDLE
ShadowLoadLibrary(
    IN  WCHAR  *lpFileName
    )
/*++

Routine Description:
    
    Map the file into memory

Arguments:

    lpFileName: file name,E.G.: L"\\Device\\HarddiskVolume1\\Windows\\system32\\ntdll.dll"

Return Value:

    If the function fails, the return value is NULL

--*/
{
    UNICODE_STRING      ustrFileName;
    OBJECT_ATTRIBUTES   ObjectAttributes = { 0 };
    IO_STATUS_BLOCK     IoStatus = { 0 };
    SIZE_T              ViewSize = 0;
    NTSTATUS            status;
    PLIBRARY_INFO       pLibraryInfo;
    
    pLibraryInfo = (PLIBRARY_INFO)ExAllocatePoolWithTag(PagedPool , sizeof(LIBRARY_INFO), 'VXer');
    if (!pLibraryInfo)
    {
        KdPrint(("[shadow] ExAllocatePoolWithTag failed\n"));
        return pLibraryInfo;
    }
    RtlInitUnicodeString(&ustrFileName, lpFileName);
    InitializeObjectAttributes(&ObjectAttributes, &ustrFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    do 
    {
        status = ZwOpenFile(&pLibraryInfo->hFile, FILE_EXECUTE | SYNCHRONIZE, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[shadow] ZwOpenFile failed\n"));
            break;
        }

        ObjectAttributes.ObjectName = NULL;
        status = ZwCreateSection(&pLibraryInfo->hSection, SECTION_ALL_ACCESS, &ObjectAttributes, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, pLibraryInfo->hFile);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[shadow] ZwCreateSection failed\n"));
            break;
        }

        status = ZwMapViewOfSection(pLibraryInfo->hSection, NtCurrentProcess(), &pLibraryInfo->pBaseAddress, 0, PAGE_SIZE, NULL, &ViewSize, ViewUnmap , MEM_TOP_DOWN, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            KdPrint(("[shadow] ZwMapViewOfSection failed\n"));
            break;
        }
    } while (FALSE);
    return pLibraryInfo;
}

NTSTATUS
ShadowFreeLibrary(
    IN HANDLE   hModule
    )
/*++

Routine Description:
    
    Unmap the view,release the section handle and file handle

Arguments:

    hModule: return from ShadowLoadLibrary

Return Value:

    If the function succeeds, the return value is STATUS_SUCCESS

--*/
{
    PLIBRARY_INFO       pLibraryInfo = (PLIBRARY_INFO)hModule;
    if (pLibraryInfo->pBaseAddress) {
        ZwUnmapViewOfSection(NtCurrentProcess(), pLibraryInfo->pBaseAddress);
    }
    if (pLibraryInfo->hSection) {
        ZwClose(pLibraryInfo->hSection);
    }
    if (pLibraryInfo->hFile) {
        ZwClose(pLibraryInfo->hFile);
    }
    ExFreePoolWithTag(pLibraryInfo, 'VXer');
    return STATUS_SUCCESS;
}