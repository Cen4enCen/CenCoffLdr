#include "LdrFuncResolve.h"

Win32Api win32Api = { 0 };

HMODULE GetModuleByPeb(DWORD dwNameHash)
{
    PPEB                pBeb                = (PPEB)__readgsqword(0x60);
    CHAR                dllName[256]        = { 0 };
    DWORD               dwHash              = 0;
    PCHAR               pDllName            = NULL;
    wchar_t* pwszDllName                    = NULL;
    PPEB_LDR_DATA	    pPebLdrData         = pBeb->Ldr;
    PLIST_ENTRY		    pListHeadNode       = &pPebLdrData->InMemoryOrderModuleList;
    PLIST_ENTRY		    pCurrentNode        = pListHeadNode->Flink;

    while (pCurrentNode != pListHeadNode)
    {
        PLDR_DATA_TABLE_ENTRY2 pLdrDataTableEntry = CONTAINING_RECORD(pCurrentNode, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);

        pwszDllName                         = GetDllName(pLdrDataTableEntry->FullDllName.Buffer);

        utf16_to_utf8(pwszDllName, StringLengthW(pwszDllName), dllName);

        pDllName                            = dllName;
        pDllName                            = StringTokenA(pDllName, ".");
        dwHash                              = HashEx(pDllName, StringLengthA(pDllName), TRUE);

        if (dwNameHash == dwHash)
        {
            return pLdrDataTableEntry->DllBase;
        }

        pCurrentNode = pCurrentNode->Flink;
    }
    return NULL;
}


BOOL LdrResolveFunction()
{
    HMODULE hNtdll = GetModuleByPeb(NTDLLHASH);
    HMODULE hKer32 = GetModuleByPeb(KERNEL32HASH);
   
    win32Api.pfnCloseHandle                         = (evaCloseHandle)GetProcAddressByHash(hKer32, CLOSEHANDLEHASH);
    win32Api.pfnReadFile                            = (evaReadFile)GetProcAddressByHash(hKer32, READFILEHASH);
    win32Api.pfnCreateFileA                         = (evaCreateFileA)GetProcAddressByHash(hKer32, CREATEFILEAHASH);
    win32Api.pfnGetFileSize                         = (evaGetFileSize)GetProcAddressByHash(hKer32, GETFILESIZEHASH);
    win32Api.pfnLdrLoadDll                          = (evaLdrLoadDll)GetProcAddressByHash(hNtdll, LDRLOADDLLHASH);
    win32Api.pfnRtlExitUserThread                   = (evaRtlExitUserThread)GetProcAddressByHash(hNtdll, RTLEXITUSERTHREADHASH);
    win32Api.pfnNtProtectVirtualMemory              = (evaNtProtectVirtualMemory)GetProcAddressByHash(hNtdll, NTPROTECTVIRTUALMEMORYHASH);
    win32Api.pfnNtCreateThreadEx                    = (evaNtCreateThreadEx)GetProcAddressByHash(hNtdll, NTCREATETHREADEXHASH);
    win32Api.pfnNtResumeThread                      = (evaNtResumeThread)GetProcAddressByHash(hNtdll, NTRESUMETHREADHASH);
    win32Api.pfnNtGetContextThread                  = (evaNtGetContextThread)GetProcAddressByHash(hNtdll, NTGETCONTEXTTHREADHASH);
    win32Api.pfnNtSetContextThread                  = (evaNtSetContextThread)GetProcAddressByHash(hNtdll, NTSETCONTEXTTHREADHASH);
    win32Api.pfnNtWaitForSingleObject               = (evaNtWaitForSingleObject)GetProcAddressByHash(hNtdll, NTWAITFORSINGLEOBJECTHASH);
    win32Api.ulTpReleaseCleanupGroupMembers         = (ULONG_PTR)GetProcAddressByHash(hNtdll,TPRELEASECLEANUPGROUPMEMBERSHASH);
    win32Api.pfnNtAllocateVirtualMemory             = (evaNtAllocateVirtualMemory)GetProcAddressByHash(hNtdll, NTALLOCATEVIRTUALMEMORYHASH);
    win32Api.pfnLdrGetProcedureAddress              = (evaLdrGetProcedureAddress)GetProcAddressByHash(hNtdll, LDRGETPROCEDUREADDRESSHASH);
    win32Api.pfnRtlAddVectoredExceptionHandler      = (evaRtlAddVectoredExceptionHandler)GetProcAddressByHash(hNtdll, RTLADDVECTOREDEXCEPTIONHANDLERHASH);
    win32Api.pfnRtlRemoveVectoredExceptionHandler   = (evaRtlRemoveVectoredExceptionHandler)GetProcAddressByHash(hNtdll, RTLREMOVEVECTOREDEXCEPTIONHANDLERHASH);
    win32Api.pfnNtQueryInformationToken             = (evaNtQueryInformationToken)GetProcAddressByHash(hNtdll, NTQUERYINFORMATIONTOKENHASH);
    win32Api.pfnNtOpenThreadToken                   = (evaNtOpenThreadToken)GetProcAddressByHash(hNtdll, NTOPENTHREADTOKENHASH);
    win32Api.pfnNtOpenProcessToken                  = (evaNtOpenProcessToken)GetProcAddressByHash(hNtdll, NTOPENPROCESSTOKENHASH);

    return (win32Api.pfnCloseHandle != NULL && win32Api.pfnReadFile != NULL && win32Api.pfnCreateFileA != NULL
        && win32Api.pfnGetFileSize != NULL && win32Api.pfnLdrLoadDll != NULL && win32Api.pfnNtProtectVirtualMemory != NULL
        && win32Api.pfnNtCreateThreadEx != NULL && win32Api.pfnNtResumeThread != NULL && win32Api.pfnNtGetContextThread != NULL 
        && win32Api.pfnNtSetContextThread != NULL && win32Api.pfnNtWaitForSingleObject != NULL && win32Api.ulTpReleaseCleanupGroupMembers != 0 
        && win32Api.pfnNtAllocateVirtualMemory != NULL && win32Api.pfnLdrGetProcedureAddress != NULL && win32Api.pfnRtlAddVectoredExceptionHandler != NULL
        && win32Api.pfnRtlRemoveVectoredExceptionHandler != NULL && win32Api.pfnNtQueryInformationToken != NULL && win32Api.pfnNtOpenThreadToken != NULL
        && win32Api.pfnNtOpenProcessToken != NULL);
}

unsigned int crc32a(char* str)
{

    unsigned int    byte, mask, crc = 0xFFFFFFFF;
    int             i = 0, j = 0;

    while (str[i] != 0)
    {
        byte = str[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--)
        {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEED & mask);
        }

        i++;
    }
    return ~crc;
}



PVOID GetProcAddressByHash(ULONG_PTR ulDllBase, DWORD dwTargetHash)
{

    PIMAGE_DOS_HEADER pImgDosHead = (PIMAGE_DOS_HEADER)ulDllBase;
    PIMAGE_NT_HEADERS modulePEHeader = (PIMAGE_NT_HEADERS)(ulDllBase + pImgDosHead->e_lfanew);


    PIMAGE_DATA_DIRECTORY	pImgExportDataDir = &modulePEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(ulDllBase + pImgExportDataDir->VirtualAddress);
    ULONG_PTR				ulNameArray = ulDllBase + pImgExportDir->AddressOfNames;
    ULONG_PTR				ulOrdinalArray = ulDllBase + pImgExportDir->AddressOfNameOrdinals;
    ULONG_PTR				ulAddressArray = ulDllBase + pImgExportDir->AddressOfFunctions;

    while (ulNameArray)
    {
        DWORD dwFunctionNameHash = crc32a((char*)(ulDllBase + *(DWORD*)(ulNameArray)));

        // Anti VDLLs / Defender emulator
        if (dwFunctionNameHash == 0x62B67FEE) __fastfail(0xc00000022);

        if (dwFunctionNameHash == dwTargetHash)
        {

            ulAddressArray += *(WORD*)(ulOrdinalArray) * sizeof(DWORD);

            return ulDllBase + *(DWORD*)(ulAddressArray);
        }

        ulNameArray += sizeof(DWORD);
        ulOrdinalArray += sizeof(WORD);
    }

    return NULL;
}
