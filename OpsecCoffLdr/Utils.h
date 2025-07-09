#pragma once
#include <Windows.h>
#include "Structs.h"

#define HASH_KEY 5391
#define COFF_PREP_TEXT           0x3dd12782
#define COFF_PREP_SYMBOL		 0x5a007272 
#define COFF_PREP_BEACON		 0x8843e5ba
#define COFF_PREP_TEXT_SIZE      5
#define COFF_PREP_SYMBOL_SIZE    6
#define COFF_PREP_BEACON_SIZE    (COFF_PREP_SYMBOL_SIZE + 6)

BOOL IsDigit(char* str);
SIZE_T StringLengthA(LPCSTR String);
SIZE_T StringLengthW(LPCWSTR String);
HMODULE GetModuleByPeb(DWORD dwNameHash);
BOOL _Memcpy(void* dest, void* src, size_t size);
PVOID _Memset(void* dest, int ch, size_t count);
INT _Strcmp(unsigned char* a, unsigned char* b);
PCHAR StringTokenA(PCHAR String, CONST PCHAR Delim);
ULONG HashEx(PVOID String, ULONG Length, BOOL Upper);
VOID utf16_to_utf8(wchar_t* wide_string, DWORD wide_string_len, BYTE* ascii_string);
wchar_t* GetDllName(const wchar_t* fullDllName);
VOID _RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
