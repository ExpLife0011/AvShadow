/*++

Copyright (c) 2009-2011  lazycat studio

Module Name:

    AvShadow.h

Abstract:

Author:

    lazy_cat

Environment:

    Kernel mode only

Revision History:

    2011-07-18: create

--*/

#ifndef _AVSHADOW_H_
#define _AVSHADOW_H_

#pragma pack(1)
typedef struct _SYSTEM_SERVICE_TABLE {
    PULONG     ServiceTableBase;
    PULONG     ServiceCounterTableBase;
    ULONG      NumberOfService;
    PCHAR      ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
#pragma pack()

#pragma pack(1)
typedef struct _SERVICE_DESCRIPTOR_TABLE {
    SYSTEM_SERVICE_TABLE    ntoskrnl;
    SYSTEM_SERVICE_TABLE    win32k;
    SYSTEM_SERVICE_TABLE    Reserved1;
    SYSTEM_SERVICE_TABLE    Reserved2;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
#pragma pack()

typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT          pDeviceObject;
    UNICODE_STRING          ustrSymbolLink;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION ;

typedef struct _EVENT_INFO{
    PKEVENT                 pUserShareEvent;
    KEVENT                  EventIoCtlDone;
    KEVENT                  EventSingleThreadSync;
} EVENT_INFO, *PEVENT_INFO;

// size:44(48)
#pragma pack(1)
typedef struct _SEGMENT_OBJECT{
    PVOID           BaseAddress;
    ULONG           TotalNumberOfPtes;
    LARGE_INTEGER   SizeOfSegment;
    ULONG           NonExtendedPtes;
    ULONG           ImageCommitment;
    PVOID           ControlArea;
    PVOID           Subsection;
    PVOID           LargeControlArea;
    PVOID           MmSectionFlags;
    PVOID           MmSubSectionFlags;
} SEGMENT_OBJECT, *PSEGMENT_OBJECT;
#pragma pack()

// size:64(72)
#pragma pack(1)
typedef struct _SECTION_OBJECT{
    ULONG           StartingVa;
    ULONG           EndingVa;
    ULONG           Parent;
    ULONG           LeftChild;
    ULONG           RightChild;
    SEGMENT_OBJECT  Segment;
} SECTION_OBJECT, *PSECTION_OBJECT;
#pragma pack()

#pragma pack(1)
typedef struct _CONTROL_AREA{
    PVOID           Segment;            // Ptr32 _SEGMENT
    LIST_ENTRY      DereferenceList;
    ULONG           NumberOfSectionReferences;
    ULONG           NumberOfPfnReferences;
    ULONG           NumberOfMappedViews;
    USHORT          NumberOfSubsections;
    USHORT          FlushInProgressCount;
    ULONG           NumberOfUserReferences;
    ULONG           reversed;
    PFILE_OBJECT    FilePointer;
    PVOID           WaitingForDeletion; // Ptr32 _EVENT_COUNTER
    USHORT          ModifiedWriteCount;
    USHORT          NumberOfSystemCacheViews;
} CONTROL_AREA, *PCONTROL_AREA;
#pragma pack()

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
    ULONG Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define ServiceIndex(ZwFunc)    (*(ULONG*)((ULONG)(ZwFunc) + 1))

#define NAKED                   __declspec(naked)
#define MEMORY_TAG              'VXer'
#define DEVICE_NAME             L"\\Device\\Avshadow"
#define SYMBOLLINK_NAME         L"\\DosDevices\\Avshadow"

/* some member in _EPROCESS struct */

// +0x1b0 Peb              : Ptr32 _PEB
#define EPROCESS_PEB_OFFSET             0x1B0
// +0x174 ImageFileName    : [16] UChar
#define EPROCESS_IMGFILENAME_LENGTH     16


/* some member in _PEB struct */

// +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
#define PROCESSPARAMETERS_OFFSET        0x010


/* some member in _RTL_USER_PROCESS_PARAMETERS struct */

// +0x038 ImagePathName    : _UNICODE_STRING
#define IMAGEPATHNAME_OFFSET            0x038


// Function Define
NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT		DriverObject,
    IN PUNICODE_STRING		RegistryPath
    );

VOID
AvshadowUnload(
    IN PDRIVER_OBJECT		DriverObject
    );

NTSTATUS
AvshadowGeneralDispatch(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	);

ULONG
GetProcessNameOffsetInEPROCESS(
    VOID
    );

PUNICODE_STRING
GetImagePathName(
    IN  PEPROCESS   pEProcess
    );

// NtOpenProcess
NTSTATUS
NTAPI
AvshadowNtOpenProcess(
    __out PHANDLE  ProcessHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PCLIENT_ID  ClientId
    );

typedef
NTSTATUS
(NTAPI *PNTOPENPROCESS)(
    __out PHANDLE  ProcessHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PCLIENT_ID  ClientId
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess(
    __out PHANDLE  ProcessHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PCLIENT_ID  ClientId
    );

// NtCreateProcessEx
typedef
NTSTATUS
(NTAPI *PNTCREATEPROCESSEX)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN HANDLE UnknownHandle
    );

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
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN HANDLE UnknownHandle
    );

// NtLoadDriver
NTSYSAPI
NTSTATUS 
NTAPI
ZwLoadDriver(
    IN PUNICODE_STRING  DriverServiceName
    );

NTSTATUS 
NTAPI
AvshadowNtLoadDriver(
    IN PUNICODE_STRING  DriverServiceName
    );

typedef
NTSTATUS 
(NTAPI *PNTLOADDRIVER)(
    IN PUNICODE_STRING  DriverServiceName
    );

// NtQuerySystemInformation
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSTATUS
NTAPI
AvshadowNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

typedef
NTSTATUS 
(NTAPI *PNTQUERYSYSTEMINFORMATION)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSTATUS
AvshadowKiSvcTabHook(
    IN  PSERVICE_DESCRIPTOR_TABLE   KeSvcDescTab,
    IN  ULONG                       pZwFunctionAddress,
    IN  ULONG                       pNewNtFunctionAddress,
    OUT ULONG                       *pNtPreviousFunctionAddress
    );

NTSTATUS
AvshadowKiSvcTabUnHook(
    IN  PSERVICE_DESCRIPTOR_TABLE   KeSvcDescTab,
    IN  ULONG                       pZwFunctionAddress,
    IN  ULONG                       pNtPreviousFunctionAddress
    );


NTSTATUS
AvshadowDispatchDeviceControl(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    );

NTSTATUS
IoQueryFileDosDeviceName(
    IN PFILE_OBJECT  FileObject,
    OUT POBJECT_NAME_INFORMATION  *ObjectNameInformation
    );

#endif  /* _AVSHADOW_H_ */