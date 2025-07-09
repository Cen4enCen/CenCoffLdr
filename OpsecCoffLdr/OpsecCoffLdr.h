#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include "ObjectApi.h"
#include "CoffStruct.h"

#define MAXARGNUM	  0x10
#define TARGETMODULE "clipwinrt.dll" // Replace Me :)


DWORD		dwBssEntryNum	= 0;
BSSEntry	BssEntry[50]	= {0}; // maybe You Will Never Use So Many Bss Var

VOID RunCoff(PCOFFEE pCoffee, CHAR* szBofEntryPoint, PVOID pvArgument, DWORD dwArgSize);
SIZE_T ParseTotalSize(PCOFFEE pCoffee, SIZE_T* stTotalSize, PSIZE_T pstBSSSize);
BOOL	CoffeeProcessSection(PCOFFEE pCoffee);
PVOID CoffeeModuleStomping(DWORD dwSize);
VOID BofPack(PVOID* pvBofArgBuf, DWORD* pdwBofArgSize, CHAR** argv);
BOOL ReadPayLoad(PBYTE* pbBofBuffer, PDWORD pdwBofSize, CHAR* szBofPath);
BOOL CoffeeProcessSymbol(PCHAR pSymbolName, PCOFF_SYMBOL pCoffSymbol, PVOID* pvFunctionAddr, PDWORD pdwBssAddr);
LONG VectoredExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo);
VOID HitCoffeeEntryPoint(PVOID pvCoffeeEntryPoint, PVOID pvArgument, DWORD dwArgSize);


	