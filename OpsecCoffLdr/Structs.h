#pragma once
#include <Windows.h>

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

#pragma pack(push,1)
typedef struct _Arg
{
    BYTE    buffer[MAX_PATH];  // we believe the arg will never to long
    UINT    num;
    UINT    length;
}Arg, PArg;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _BSSEntry
{
    PVOID  pvSysmbolAddr; 
    SIZE_T stOffset;
}BSSEntry, PBSSEntry;
#pragma pack(pop)


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;
typedef _Function_class_(USER_THREAD_START_ROUTINE)NTSTATUS NTAPI USER_THREAD_START_ROUTINE(PVOID);
typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;
typedef const ANSI_STRING* PCANSI_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef VOID(*evaRtlExitUserThread)(NTSTATUS);
typedef  BOOL(*evaCloseHandle)(HANDLE);
typedef  BOOL(*evaReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef  BOOL(*evaUnmapViewOfFile)(LPCVOID);
typedef  DWORD(*evaGetFileSize)(HANDLE, LPDWORD);
typedef  LPVOID(*evaMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef  HANDLE(*evaCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef  NTSTATUS(*evaLdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef  NTSTATUS(*evaNtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef  NTSTATUS(*evaNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PUSER_THREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef  NTSTATUS(*evaNtGetContextThread)(HANDLE, PCONTEXT);
typedef  NTSTATUS(*evaNtSetContextThread)(HANDLE, PCONTEXT);
typedef  NTSTATUS(*evaNtResumeThread)(HANDLE, PULONG);
typedef  NTSTATUS(*evaNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef  NTSTATUS(*evaNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef  NTSTATUS(*evaLdrGetProcedureAddress)(PVOID,PCANSI_STRING,ULONG,PVOID*);
typedef  NTSTATUS(*evaRtlAddVectoredExceptionHandler)(ULONG,PVECTORED_EXCEPTION_HANDLER);
typedef  NTSTATUS(*evaRtlRemoveVectoredExceptionHandler)(PVECTORED_EXCEPTION_HANDLER);
typedef  NTSTATUS(*evaNtQueryInformationToken)(HANDLE,TOKEN_INFORMATION_CLASS,PVOID,ULONG,PULONG);
typedef  NTSTATUS(*evaNtOpenThreadToken)(HANDLE,ACCESS_MASK,BOOLEAN,PHANDLE);
typedef  NTSTATUS(*evaNtOpenProcessToken)(HANDLE ,ACCESS_MASK,PHANDLE);

typedef struct _Win32Api
{
    evaReadFile                             pfnReadFile;
    evaLdrLoadDll                           pfnLdrLoadDll;
    evaCloseHandle                          pfnCloseHandle;
    evaCreateFileA                          pfnCreateFileA;
    evaGetFileSize                          pfnGetFileSize;
    evaNtResumeThread                       pfnNtResumeThread;
    evaNtCreateThreadEx                     pfnNtCreateThreadEx;
    evaRtlExitUserThread                    pfnRtlExitUserThread;
    evaNtOpenThreadToken                    pfnNtOpenThreadToken;
    evaNtGetContextThread                   pfnNtGetContextThread;
    evaNtSetContextThread                   pfnNtSetContextThread;
    evaNtOpenProcessToken                   pfnNtOpenProcessToken;
    evaNtWaitForSingleObject                pfnNtWaitForSingleObject;
    evaNtProtectVirtualMemory               pfnNtProtectVirtualMemory;
    evaNtAllocateVirtualMemory              pfnNtAllocateVirtualMemory;
    evaLdrGetProcedureAddress               pfnLdrGetProcedureAddress;
    evaNtQueryInformationToken              pfnNtQueryInformationToken;
    evaRtlAddVectoredExceptionHandler       pfnRtlAddVectoredExceptionHandler;
    evaRtlRemoveVectoredExceptionHandler    pfnRtlRemoveVectoredExceptionHandler;
    ULONG_PTR                               ulTpReleaseCleanupGroupMembers;
}Win32Api, * PWin32Api;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY2
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
} LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY2;