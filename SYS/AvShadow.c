/*++

Copyright (c) 2009-2011  lazycat studio

Module Name:

    AvShadow.c

Abstract:

	Avshadow HIPS kernel driver

Author:

    lazy_cat

Environment:

    Kernel mode only

Revision History:

    2011-07-18: create

--*/

#include <ntddk.h>
#include <ntstrsafe.h>
#include "AvShadow.h"
#include "Kernel32.h"
#include "../EXE/AvShadowIoCtrl.h"


#ifdef  ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AvshadowUnload)
#endif  /* ALLOC_PRAGMA */


// GLOBAL
extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;

ULONG                               g_ulProcessNameOffsetInEPROCESS = 0;
ULONG                               g_ulZwCreateProcessExServiceIndex = 0;
PNTOPENPROCESS                      g_pNtOpenProcess = 0;
PNTCREATEPROCESSEX                  g_pNtCreateProcessEx = 0;
PNTLOADDRIVER                       g_pNtLoadDriver = 0;
PNTQUERYSYSTEMINFORMATION           g_pNtQuerySystemInformation = 0;

OPEN_PROCESS_INFO                   g_OpenProcessInfo = { PacketOpenProcess, 0 };
CREATE_PROCESSEX_INFO               g_CreateProcessExInfo = { 0 };
LOAD_DRIVER_INFO                    g_LoadDriverInfo = { 0 };

PEVENT_INFO                         g_EventTable    = NULL;
PWHITE_LIST                         g_pWhiteList    = NULL;
ULONG                               g_ulAvExePID    = 0;
ULONG                               g_ulProtectFlags = 0;


NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT		DriverObject,
	IN PUNICODE_STRING		RegistryPath
	)
{
	NTSTATUS			status;
    UNICODE_STRING      ustrDeviceName;
    PDEVICE_OBJECT      pDevObject;
    PDEVICE_EXTENSION   pDevExt;
    int                 i;

    // Create device and symbol link used for user application
    RtlInitUnicodeString(&ustrDeviceName, DEVICE_NAME);
    status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &ustrDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObject);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[shadow] IoCreateDevice failed\n"));
        return status;
    }
    pDevObject->Flags |= DO_BUFFERED_IO;
    pDevExt = pDevObject->DeviceExtension;
    pDevExt->pDeviceObject = pDevObject;
    RtlInitUnicodeString(&pDevExt->ustrSymbolLink, SYMBOLLINK_NAME);

    status = IoCreateSymbolicLink(&pDevExt->ustrSymbolLink, &ustrDeviceName);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("[shadow] IoCreateSymbolicLink failed\n"));
        IoDeleteDevice(pDevObject);
        return status;
    }

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = AvshadowGeneralDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AvshadowDispatchDeviceControl;
    DriverObject->DriverUnload = AvshadowUnload;

    g_ulProcessNameOffsetInEPROCESS = GetProcessNameOffsetInEPROCESS();
    return  status;
}


VOID
AvshadowUnload(
	IN PDRIVER_OBJECT		DriverObject
	)
{
    PDEVICE_EXTENSION   pDevExt = (PDEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;
    // What a fucking bug!
    RtlInitUnicodeString(&pDevExt->ustrSymbolLink, SYMBOLLINK_NAME);
    IoDeleteSymbolicLink(&pDevExt->ustrSymbolLink);
    IoDeleteDevice(pDevExt->pDeviceObject);
    // unhook
    if (g_ulProtectFlags & ENABLE_OPENPROCESS && g_pNtOpenProcess) {
        AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwOpenProcess), (ULONG)g_pNtOpenProcess);
        KdPrint(("[shadow] NtOpenProcess has been unhooked\n"));

    }
    if (g_ulProtectFlags & ENABLE_CREATEPROCESSEX && g_pNtCreateProcessEx) {
        AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwOpenProcess), (ULONG)g_pNtOpenProcess);
        KdPrint(("[shadow] NtOpenProcess has been unhooked\n"));
    }
    if (g_ulProtectFlags & ENABLE_LOADDRIVER && g_pNtLoadDriver) {
        AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwLoadDriver), (ULONG)g_pNtLoadDriver);
        KdPrint(("[shadow] NtLoadDriver has been unhooked\n"));
    }
    // Release while list table
    if (g_pWhiteList) {
        ExFreePoolWithTag(g_pWhiteList, MEMORY_TAG);
    }
    KdPrint(("[shadow] Avshadow.sys has unloaded\n"));
}


NTSTATUS
AvshadowGeneralDispatch(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	)
/*++

Routine Description:

    CreateFile CloseHandle

--*/
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    switch (IrpSp->MajorFunction)
    {
    case IRP_MJ_CREATE:
        break;
    case IRP_MJ_CLEANUP:
        break;
    case IRP_MJ_CLOSE:
        break;
    default:
        KdPrint(("[shadow] Unknown IRP request\n"));
        break;
    }
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return	STATUS_SUCCESS;
}


NTSTATUS
AvshadowKiSvcTabHook(
    IN  PSERVICE_DESCRIPTOR_TABLE   KeSvcDescTab,
    IN  ULONG                       ulServiceIndex,
    IN  ULONG                       pNewNtFunctionAddress,
    OUT ULONG                       *pNtPreviousFunctionAddress
    )
{
    // *pNtPreviousFunctionAddress = KeSvcDescTab->ntoskrnl.ServiceTableBase[ServiceIndex(pZwFunctionAddress)];
    // KeSvcDescTab->ntoskrnl.ServiceTableBase[ServiceIndex(pZwFunctionAddress)] = pNewNtFunctionAddress;
    *pNtPreviousFunctionAddress = InterlockedExchange(&KeSvcDescTab->ntoskrnl.ServiceTableBase[ulServiceIndex], pNewNtFunctionAddress);
    return STATUS_SUCCESS;
}


NTSTATUS
AvshadowKiSvcTabUnHook(
    IN  PSERVICE_DESCRIPTOR_TABLE   KeSvcDescTab,
    IN  ULONG                       ulServiceIndex,
    IN  ULONG                       pNtPreviousFunctionAddress
    )
{
    InterlockedExchange(&KeSvcDescTab->ntoskrnl.ServiceTableBase[ulServiceIndex], pNtPreviousFunctionAddress);
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
AvshadowNtOpenProcess(
    OUT PHANDLE             ProcessHandle,
    IN  ACCESS_MASK         DesiredAccess,
    IN  POBJECT_ATTRIBUTES  ObjectAttributes,
    IN  PCLIENT_ID          ClientId
    )
{
    NTSTATUS        status;
    BOOLEAN         bAllow = FALSE;
    PUNICODE_STRING pImagePath = NULL;
    UNICODE_STRING  ustrOmitPath;
    WCHAR           *pLastStringAddress;
    ULONG           i = 0;

    KdPrint(("\n\n\n[shadow] Enter AvshadowNtOpenProcess\n"));
    if (!(g_ulProtectFlags & ENABLE_OPENPROCESS))
    {
        KdPrint(("[shadow] NtOpenProcess protected flag is not enable,directly allow\n"));
        KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
        return g_pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    // Self open self,return directly
    if (PsGetCurrentProcessId() == ClientId->UniqueProcess) {
        KdPrint(("[shadow] AvshadowNtOpenProcess: self open self,directly allow\n"));
        KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
        return g_pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    
    // If it's our request,return directly
    if (g_ulAvExePID == (ULONG)PsGetCurrentProcessId()) {
        KdPrint(("[shadow] AvshadowNtOpenProcess: Avshadow.exe,directly allow\n"));
        KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
        return g_pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    // If some one try to open me,I can kill it
    if (g_ulAvExePID == (ULONG)ClientId->UniqueProcess) {
        return STATUS_ACCESS_DENIED;
    }
 
    // If the image path is in the white list,directly return
    pImagePath = GetImagePathName(PsGetCurrentProcess());
    pLastStringAddress = (WCHAR*)((ULONG)g_pWhiteList + 8);
    for (i = 0; i < g_pWhiteList->ulStringCount; i++)
    {
        if ((WCHAR)'*' == pLastStringAddress[wcslen(pLastStringAddress) - 1])
        {
            if (!_wcsnicmp(pLastStringAddress, pImagePath->Buffer, wcslen(pLastStringAddress) - 1)) {
                KdPrint(("[shadow] Process:%ws is in the white list,directly allow\n", pImagePath->Buffer));
                KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
                return g_pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
            }
        }
        else
        {
            if (!_wcsicmp(pLastStringAddress, pImagePath->Buffer)) {
                KdPrint(("[shadow] Process:%ws is in the white list,directly allow\n", pImagePath->Buffer));
                KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
                return g_pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
            }
        }
        pLastStringAddress += wcslen(pLastStringAddress) + 1;        
    }

    while (!NT_SUCCESS(KeWaitForSingleObject(&g_EventTable[EVENT_INDEX_OPENPROCESS].EventSingleThreadSync, Executive, KernelMode, FALSE, NULL)));
    g_OpenProcessInfo.ulProcessID = PsGetCurrentProcessId();
    RtlZeroMemory(g_OpenProcessInfo.szProcessName, sizeof(CHAR[MAX_PROCESSNAME_LENGTH]));
    strncpy(g_OpenProcessInfo.szProcessName, (CHAR*)PsGetCurrentProcess() + g_ulProcessNameOffsetInEPROCESS, EPROCESS_IMGFILENAME_LENGTH);
    g_OpenProcessInfo.ulTargetProcessID = ClientId->UniqueProcess;
    
    if (pImagePath) {
        RtlZeroMemory(g_OpenProcessInfo.szImagePath, sizeof(WCHAR[256]));
        RtlCopyMemory(g_OpenProcessInfo.szImagePath, pImagePath->Buffer, pImagePath->Length);
    }

    // Set the event to signal state,so in the user mode application, the WaitForSingleObject will return
    KeSetEvent(g_EventTable[EVENT_INDEX_OPENPROCESS].pUserShareEvent, IO_NO_INCREMENT, FALSE);

    // Wait for the IOCTL's progress
    while (!NT_SUCCESS(KeWaitForSingleObject(&g_EventTable[EVENT_INDEX_OPENPROCESS].EventIoCtlDone, Executive, KernelMode, FALSE, NULL)));

    bAllow = g_OpenProcessInfo.bAllowed;
    KeSetEvent(&g_EventTable[EVENT_INDEX_OPENPROCESS].EventSingleThreadSync, IO_NO_INCREMENT, FALSE);  // thread

    if (bAllow) {
        KdPrint(("[shadow] The user allow the operation\n"));
        KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
        return g_pNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    else {
        KdPrint(("[shadow] The user deny the operation\n"));
        KdPrint(("[shadow] Exit AvshadowNtOpenProcess\n"));
        return STATUS_ACCESS_DENIED;
    }
}


NTSTATUS
NTAPI
AvshadowNtCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN HANDLE UnknownHandle
    )
{
    PVOID               pParrentEProcess = NULL;
    PSECTION_OBJECT     pSectionObject   = NULL;
    PFILE_OBJECT        pFileObject      = NULL;
    PCONTROL_AREA       pControlArea     = NULL;
    BOOLEAN             bAllowed;
    NTSTATUS            status;
    PUNICODE_STRING     pImagePath = NULL;
    POBJECT_NAME_INFORMATION    pObjNameInfo = NULL;

    KdPrint(("\n\n\n[shadow] Enter AvshadowNtCreateProcessEx\n"));      // thread 
    if (!(g_ulProtectFlags & ENABLE_CREATEPROCESSEX))
    {
        KdPrint(("[shadow] NtCreateProcessEx protected flag is not enable,directly allow\n"));
        KdPrint(("[shadow] Exit AvshadowNtCreateProcessEx\n"));
        return g_pNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort, UnknownHandle);
    }

    KeWaitForSingleObject(&g_EventTable[EVENT_INDEX_CREATEPROCESSEX].EventSingleThreadSync, Executive, KernelMode, FALSE, NULL);

    // Get some information
    g_CreateProcessExInfo.ulProcessID = PsGetCurrentProcessId();
    if (pImagePath = GetImagePathName(PsGetCurrentProcess()))
    {
        RtlZeroMemory(g_CreateProcessExInfo.szImagePath, sizeof(WCHAR[256]));
        RtlCopyMemory(g_CreateProcessExInfo.szImagePath, pImagePath->Buffer, pImagePath->Length);
    }
    status = ObReferenceObjectByHandle(ParentProcess, 0, NULL, KernelMode, &pParrentEProcess, NULL);
    if (NT_SUCCESS(status)) {
        // ANSI string
        RtlZeroMemory(g_CreateProcessExInfo.szParentProcessName, sizeof(CHAR[MAX_PROCESSNAME_LENGTH]));
        strncpy(g_CreateProcessExInfo.szParentProcessName, (CHAR*)pParrentEProcess + g_ulProcessNameOffsetInEPROCESS, EPROCESS_IMGFILENAME_LENGTH);
    }
    ObDereferenceObject(pParrentEProcess);

    // what process it will create
    status = ObReferenceObjectByHandle(SectionHandle, 0, NULL, KernelMode, &pSectionObject, NULL);
    if (NT_SUCCESS(status)) {
        pControlArea = *(PCONTROL_AREA*)(pSectionObject->Segment.BaseAddress);
        pFileObject = pControlArea->FilePointer;
        status = IoQueryFileDosDeviceName(pFileObject, &pObjNameInfo);
        if (NT_SUCCESS(status)) {
            RtlZeroMemory(g_CreateProcessExInfo.szImagePathToCreateProcess, sizeof(WCHAR[256]));
            RtlCopyMemory(g_CreateProcessExInfo.szImagePathToCreateProcess, pObjNameInfo->Name.Buffer, pObjNameInfo->Name.Length);
        }
        ExFreePool(pObjNameInfo);
    }
    ObDereferenceObject(pSectionObject);

    // Set the event to signal state,so in the user mode application, the WaitForSingleObject will return
    KeSetEvent(g_EventTable[EVENT_INDEX_CREATEPROCESSEX].pUserShareEvent, IO_NO_INCREMENT, FALSE);
    // Wait for the IOCTL's progress
    KeWaitForSingleObject(&g_EventTable[EVENT_INDEX_CREATEPROCESSEX].EventIoCtlDone, Executive, KernelMode, FALSE, NULL);
    bAllowed = g_CreateProcessExInfo.bAllowed;
    KeSetEvent(&g_EventTable[EVENT_INDEX_CREATEPROCESSEX].EventSingleThreadSync, IO_NO_INCREMENT, FALSE);

    if (bAllowed) {
        KdPrint(("[shadow] The user allow the operation\n"));
        KdPrint(("[shadow] Exit AvshadowNtCreateProcessEx\n"));
        return g_pNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort, UnknownHandle);
    }
    else {
        KdPrint(("[shadow] The user deny the operation\n"));
        KdPrint(("[shadow] Exit AvshadowNtCreateProcessEx\n"));
        return STATUS_ACCESS_DENIED;
    }
}


NTSTATUS 
NTAPI
AvshadowNtLoadDriver(
    IN PUNICODE_STRING  DriverServiceName
    )
{
    BOOLEAN         bAllowed;
    PUNICODE_STRING pImagePath = NULL;
    OBJECT_ATTRIBUTES   ObjectAttributes;
    HANDLE              hKey;
    UNICODE_STRING      ustrValueName;
    PKEY_VALUE_PARTIAL_INFORMATION   pKeyValueInfo = NULL;
    ULONG               ulResultLength = 0;

    NTSTATUS        status;
    if (!(g_ulProtectFlags & ENABLE_LOADDRIVER))
    {
        KdPrint(("[shadow] AvshadowNtLoadDriver protected flag is not enable,directly allow\n"));
        return g_pNtLoadDriver(DriverServiceName);
    }
    KeWaitForSingleObject(&g_EventTable[EVENT_INDEX_LOADDRIVER].EventSingleThreadSync, Executive, KernelMode, FALSE, NULL);
    RtlZeroMemory(g_LoadDriverInfo.szRegPath, sizeof(WCHAR[256]));
    RtlCopyMemory(g_LoadDriverInfo.szRegPath, DriverServiceName->Buffer, DriverServiceName->Length);
    g_LoadDriverInfo.ulProcessID = PsGetCurrentProcessId();
    pImagePath = GetImagePathName(PsGetCurrentProcess());
    if (pImagePath)
    {
        RtlZeroMemory(g_LoadDriverInfo.szImagePath, sizeof(WCHAR[256]));
        RtlCopyMemory(g_LoadDriverInfo.szImagePath, pImagePath->Buffer, pImagePath->Length);
    }
    // Get the driver file path in the reg
    InitializeObjectAttributes(&ObjectAttributes, DriverServiceName, OBJ_CASE_INSENSITIVE, 0, NULL);
    status = ZwOpenKey(&hKey, GENERIC_READ, &ObjectAttributes);
    if (NT_SUCCESS(status))
    {
        RtlInitUnicodeString(&ustrValueName, L"ImagePath");
        status = ZwQueryValueKey(hKey, &ustrValueName, KeyValuePartialInformation, NULL, 0, &ulResultLength);
        if (STATUS_BUFFER_OVERFLOW == status || STATUS_BUFFER_TOO_SMALL == status)
        {
            pKeyValueInfo = ExAllocatePoolWithTag(PagedPool, ulResultLength, MEMORY_TAG);
            status = ZwQueryValueKey(hKey, &ustrValueName, KeyValuePartialInformation, pKeyValueInfo, ulResultLength, &ulResultLength);
            if (NT_SUCCESS(status))
            {
                RtlZeroMemory(g_LoadDriverInfo.szSysFilePath, sizeof(WCHAR[256]));
                RtlCopyMemory(g_LoadDriverInfo.szSysFilePath, pKeyValueInfo->Data, pKeyValueInfo->DataLength);
            }
            ExFreePoolWithTag(pKeyValueInfo, MEMORY_TAG);
        }
        ZwClose(hKey);
    }
    KeSetEvent(g_EventTable[EVENT_INDEX_LOADDRIVER].pUserShareEvent, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(&g_EventTable[EVENT_INDEX_LOADDRIVER].EventIoCtlDone, Executive, KernelMode, FALSE, NULL);
    bAllowed = g_LoadDriverInfo.bAllowed;
    KeSetEvent(&g_EventTable[EVENT_INDEX_LOADDRIVER].EventSingleThreadSync, IO_NO_INCREMENT, FALSE);
    if (bAllowed) {
        return g_pNtLoadDriver(DriverServiceName);
    }
    else {
        return STATUS_ACCESS_DENIED;
    }
}


NTSTATUS
NTAPI
AvshadowNtDeleteFile(
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    )
{
    return STATUS_SUCCESS;
}


NTSTATUS
NTAPI
AvshadowNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    )
{
    PSYSTEM_MODULE_INFORMATION  pSysMdlInfo = NULL;
    NTSTATUS    status;
    status = g_pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (NT_SUCCESS(status) && g_ulProtectFlags & ENABLE_QUERYSYSTEMINFO)
    {
        switch (SystemInformationClass)
        {
        case SystemModuleInformation:
            // Fuck the user mode's anti-ssdt tools
            pSysMdlInfo = (PSYSTEM_MODULE_INFORMATION)((ULONG)SystemInformation + 4);
            RtlZeroMemory(pSysMdlInfo, sizeof(SYSTEM_MODULE_INFORMATION));
            break;
        }
    }
    return status;
}


NTSTATUS
AvshadowDispatchDeviceControl(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
/*++

Routine Description:

    This routine is called only by one user process,so it will not be concurrent.

--*/
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID               pInOutBuffer = (POPEN_PROCESS_INFO)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS            status = STATUS_SUCCESS;
    HMODULE             hModule;
    LPVOID              lpZwCreateProcessEx;
    ULONG               ulShareEventCount = 0;
    ULONG               ulInputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG               ulOutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG               i = 0;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_AVSHADOW_GET_OPENPROCESS:
        // User mode application call this IOCTL to get which process call NtOpenProcess
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_OPENPROCESS come...\n"));
        if (sizeof(OPEN_PROCESS_INFO) == ulOutputBufferLength)
        {
            RtlCopyMemory(pInOutBuffer, &g_OpenProcessInfo, sizeof(OPEN_PROCESS_INFO));
            Irp->IoStatus.Information = sizeof(OPEN_PROCESS_INFO);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            KdPrint(("[shadow] Invalid buffer size in DeviceIoControl\n"));
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_OPENPROCESS over...\n"));
        break;

    case IOCTL_AVSHADOW_SET_OPENPROCESS:
        // User mode application will call this IOCTL after user choose the action(allow or deny)
        // In our Nt~ function,it's also wait for the under event object
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_OPENPROCESS come...\n"));
        if (sizeof(BOOLEAN) == ulInputBufferLength)
        {
            g_OpenProcessInfo.bAllowed = *(BOOLEAN*)pInOutBuffer;
            KeSetEvent(&g_EventTable[EVENT_INDEX_OPENPROCESS].EventIoCtlDone, IO_NO_INCREMENT, FALSE);
        }
        else {
            KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_OPENPROCESS over...\n"));
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_OPENPROCESS over...\n"));
        break;

    case IOCTL_AVSHADOW_GET_CREATEPROCESSEX:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_CREATEPROCESSEX come...\n"));
        if (sizeof(CREATE_PROCESSEX_INFO) == ulOutputBufferLength)
        {
            RtlCopyMemory(pInOutBuffer, &g_CreateProcessExInfo, sizeof(CREATE_PROCESSEX_INFO));
            Irp->IoStatus.Information = sizeof(CREATE_PROCESSEX_INFO);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            KdPrint(("[shadow] Invalid buffer size in DeviceIoControl\n"));
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_CREATEPROCESSEX over...\n"));
        break;

    case IOCTL_AVSHADOW_SET_CREATEPROCESSEX:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_CREATEPROCESSEX come...\n"));
        if (sizeof(BOOLEAN) == ulInputBufferLength)
        {
            g_CreateProcessExInfo.bAllowed = *(BOOLEAN*)pInOutBuffer;
            KeSetEvent(&g_EventTable[EVENT_INDEX_CREATEPROCESSEX].EventIoCtlDone, IO_NO_INCREMENT, FALSE);
        }
        else {
            KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_OPENPROCESS over...\n"));
        }        
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_CREATEPROCESSEX over...\n"));
        break;

    case IOCTL_AVSHADOW_GET_LOADDRIVER:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_LOADDRIVER come...\n"));
        if (sizeof(LOAD_DRIVER_INFO) == ulOutputBufferLength)
        {
            RtlCopyMemory(pInOutBuffer, &g_LoadDriverInfo, sizeof(LOAD_DRIVER_INFO));
            Irp->IoStatus.Information = sizeof(LOAD_DRIVER_INFO);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            KdPrint(("[shadow] Invalid buffer size in DeviceIoControl\n"));
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_LOADDRIVER over...\n"));
        break;

    case IOCTL_AVSHADOW_SET_LOADDRIVER:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_LOADDRIVER come...\n"));
        if (sizeof(BOOLEAN) == ulInputBufferLength)
        {
            g_LoadDriverInfo.bAllowed = *(BOOLEAN*)pInOutBuffer;
            KeSetEvent(&g_EventTable[EVENT_INDEX_LOADDRIVER].EventIoCtlDone, IO_NO_INCREMENT, FALSE);
        }
        else {
            KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_GET_OPENPROCESS over...\n"));
        } 
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_LOADDRIVER over...\n"));
        break;

    // 
    case IOCTL_AVSHADOW_START_OPENPROCESS:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_HOOK come...\n"));
        if (!(g_ulProtectFlags & ENABLE_OPENPROCESS))
        {
            AvshadowKiSvcTabHook(KeServiceDescriptorTable, ServiceIndex(ZwOpenProcess), (ULONG)AvshadowNtOpenProcess, (ULONG*)&g_pNtOpenProcess);
            g_ulProtectFlags |= ENABLE_OPENPROCESS;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_HOOK over...\n"));
        break;

    case IOCTL_AVSHADOW_START_CREATEPROCESSEX:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_CREATEPROCESSEX come...\n"));
        if (!(g_ulProtectFlags & ENABLE_CREATEPROCESSEX))
        {
            if (!(hModule = ShadowLoadLibrary(L"\\Device\\HarddiskVolume1\\Windows\\system32\\ntdll.dll"))) {
                KdPrint(("[shadow] ShadowLoadLibrary failed\n"));
            }
            if (lpZwCreateProcessEx = ShadowGetProcAddress(hModule, "ZwCreateProcessEx")) {
                KdPrint(("[shadow] Proc Address is 0x%08X\n", lpZwCreateProcessEx));
            }
            else {
                KdPrint(("[shadow] ShadowGetProcAddress failed,cann't find the target\n"));
            }
            g_ulZwCreateProcessExServiceIndex = ServiceIndex(lpZwCreateProcessEx);
            if (!NT_SUCCESS(ShadowFreeLibrary(hModule))) {
                KdPrint(("[shadow] ShadowFreeLibrary failed\n"));
            }
            AvshadowKiSvcTabHook(KeServiceDescriptorTable, g_ulZwCreateProcessExServiceIndex, (ULONG)AvshadowNtCreateProcessEx, (ULONG*)&g_pNtCreateProcessEx);
            g_ulProtectFlags |= ENABLE_CREATEPROCESSEX;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_CREATEPROCESSEX over...\n"));
        break;

    case IOCTL_AVSHADOW_START_LOADDRIVER:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_LOADDRIVER come...\n"));
        if (!(g_ulProtectFlags & ENABLE_LOADDRIVER))
        {
            AvshadowKiSvcTabHook(KeServiceDescriptorTable, ServiceIndex(ZwLoadDriver), (ULONG)AvshadowNtLoadDriver, (ULONG*)&g_pNtLoadDriver);
            g_ulProtectFlags |= ENABLE_LOADDRIVER;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_LOADDRIVER exit...\n"));
        break;

    case IOCTL_AVSHADOW_START_QUERYSYSINFO:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_QUERYSYSINFO come...\n"));
        if (!(g_ulProtectFlags & ENABLE_QUERYSYSTEMINFO))
        {
            AvshadowKiSvcTabHook(KeServiceDescriptorTable, ServiceIndex(ZwQuerySystemInformation), (ULONG)AvshadowNtQuerySystemInformation, (ULONG*)&g_pNtQuerySystemInformation);
            g_ulProtectFlags |= ENABLE_QUERYSYSTEMINFO;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_START_QUERYSYSINFO exit...\n"));
        break;

    //
    case IOCTL_AVSHADOW_INIT:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_INIT come...\n"));
        if (sizeof(ULONG) == ulInputBufferLength) {
            g_ulAvExePID = *(ULONG*)pInOutBuffer;
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_INIT over...\n"));
        break;

    case IOCTL_AVSHADOW_SET_EVENTHANDLE:
        // Get the event object's pointer by the handle passed from user mode
        // Create some other event object to sync between ioctl and Nt~,every Nt~ thread
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SETEVENTHANDLE come...\n"));
        if (g_EventTable)
        {
            ExFreePoolWithTag(g_EventTable, MEMORY_TAG);
            g_EventTable = NULL;
        }
        ulShareEventCount = ulInputBufferLength >> 2;
        if (g_EventTable = (PEVENT_INFO)ExAllocatePoolWithTag(PagedPool, ulShareEventCount * sizeof(EVENT_INFO), MEMORY_TAG)) {
            RtlZeroMemory(g_EventTable, IrpSp->Parameters.DeviceIoControl.InputBufferLength);
            for (i = 0; i < ulShareEventCount; i++)
            {
                status = ObReferenceObjectByHandle(((HANDLE*)pInOutBuffer)[i], EVENT_MODIFY_STATE, *ExEventObjectType, KernelMode, &g_EventTable[i].pUserShareEvent, NULL);
                if (!NT_SUCCESS(status)) {
                    KdPrint(("[shadow] ObReferenceObjectByHandle failed in AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SETEVENTHANDLE\n"));
                }
                else {
                    ObDereferenceObject(g_EventTable[i].pUserShareEvent);
                }
                KeInitializeEvent(&g_EventTable[i].EventIoCtlDone, SynchronizationEvent, FALSE);
                KeInitializeEvent(&g_EventTable[i].EventSingleThreadSync, SynchronizationEvent, TRUE);
            }
        }
        else {
            KdPrint(("[shadow] ExAllocatePoolWithTag failed in AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SET_EVENTHANDLE\n"));
        }       
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_SETEVENTHANDLE over...\n"));
        break;

    case IOCTL_AVSHADOW_INIT_WHITELIST:
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_INIT_WHITELIST come...\n"));
        if (g_pWhiteList)
        {
            ExFreePoolWithTag(g_pWhiteList, MEMORY_TAG);
            g_pWhiteList = NULL;
        }
        g_pWhiteList = (PWHITE_LIST)ExAllocatePoolWithTag(PagedPool, ((PWHITE_LIST)pInOutBuffer)->ulStringSize + sizeof(WHITE_LIST) - 4, MEMORY_TAG);
        if (g_pWhiteList)
        {
            g_pWhiteList->ulStringCount = ((PWHITE_LIST)pInOutBuffer)->ulStringCount;
            g_pWhiteList->ulStringSize = ((PWHITE_LIST)pInOutBuffer)->ulStringSize;
            RtlCopyMemory((CHAR*)g_pWhiteList + 8, (CHAR*)pInOutBuffer + 8, g_pWhiteList->ulStringSize);
        }
        else {
            KdPrint(("[shadow] ExAllocatePoolWithTag failed:IOCTL_AVSHADOW_INIT_WHITELIST\n"));
        }
        KdPrint(("[shadow] AvshadowDispatchDeviceControl - IOCTL_AVSHADOW_INIT_WHITELIST over...\n"));
        break;

    case IOCTL_AVSHADOW_GET_PROTECTFLAG:
        if (sizeof(ULONG) == ulOutputBufferLength)
        {
            RtlCopyMemory(pInOutBuffer, &g_ulProtectFlags, sizeof(ULONG));
            Irp->IoStatus.Information = sizeof(ULONG);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            KdPrint(("[shadow] Invalid buffer size in DeviceIoControl\n"));
            Irp->IoStatus.Information = 0;
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_AVSHADOW_PAUSE_OPENPROCESS:
        g_ulProtectFlags &= ~ENABLE_OPENPROCESS;
        break;

    case IOCTL_AVSHADOW_PAUSE_CREATEPROCESSEX:
        g_ulProtectFlags &= ~ENABLE_CREATEPROCESSEX;
        break;

    case IOCTL_AVSHADOW_PAUSE_LOADDRIVER:
        g_ulProtectFlags &= ~ENABLE_LOADDRIVER;
        break;

    case IOCTL_AVSHADOW_PAUSE_QUERYSYSINFO:
        g_ulProtectFlags &= ~ENABLE_QUERYSYSTEMINFO;
        break;

    case IOCTL_AVSHADOW_STOP_OPENPROCESS:
        if (g_ulProtectFlags & ENABLE_OPENPROCESS && g_pNtOpenProcess) {
            AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwOpenProcess), (ULONG)g_pNtOpenProcess);
            KdPrint(("[shadow] NtOpenProcess has been unhooked\n"));
        }
        break;

    case IOCTL_AVSHADOW_STOP_CREATEPROCESSEX:
        if (g_ulProtectFlags & ENABLE_CREATEPROCESSEX && g_pNtCreateProcessEx) {
            AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwOpenProcess), (ULONG)g_pNtOpenProcess);
            KdPrint(("[shadow] NtOpenProcess has been unhooked\n"));
        }
        break;

    case IOCTL_AVSHADOW_STOP_LOADDRIVER:
        if (g_ulProtectFlags & ENABLE_LOADDRIVER && g_pNtLoadDriver) {
            AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwLoadDriver), (ULONG)g_pNtLoadDriver);
            KdPrint(("[shadow] NtLoadDriver has been unhooked\n"));
        }
        break;

    case IOCTL_AVSHADOW_STOP_QUERYSYSINFO:
        if (g_ulProtectFlags & ENABLE_QUERYSYSTEMINFO && g_pNtQuerySystemInformation) {
            AvshadowKiSvcTabUnHook(KeServiceDescriptorTable, ServiceIndex(ZwQuerySystemInformation), (ULONG)g_pNtQuerySystemInformation);
            KdPrint(("[shadow] NtQuerySystemInformation has been unhooked\n"));
        }
        break;

    default:
        KdPrint(("[shadow] Unknown IOCTL is requested\n"));
        break;
    }
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


ULONG
GetProcessNameOffsetInEPROCESS(
    VOID
    )
{
    PEPROCESS   pEProcess = PsGetCurrentProcess();
    ULONG       ulOffset = 0;
    int         i;
    for (i = 0; ; i++)
    {
        if ( !strcmp((CHAR*)pEProcess + i, "System") )
            return i;
    }
    return 0;
}


NAKED
PUNICODE_STRING
GetImagePathName(
    IN  PEPROCESS   pEProcess
    )
{
    __asm
    {
        push    ebp
        mov     ebp,esp
        mov     eax,[ebp + 8]
        cmp     eax,0
        jz      NullPtr
        mov     eax,dword ptr [eax + EPROCESS_PEB_OFFSET]
        cmp     eax,0
        jz      NullPtr
        mov     eax,dword ptr [eax + PROCESSPARAMETERS_OFFSET]
        cmp     eax,0
        jz      NullPtr
        lea     eax,[eax + IMAGEPATHNAME_OFFSET]
        pop     ebp
        ret     4
NullPtr:
        xor     eax,eax
        pop     ebp
        ret     4
    }
}
