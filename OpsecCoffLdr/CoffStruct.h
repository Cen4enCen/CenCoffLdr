#pragma once
#include <Windows.h>

#define SIZE_OF_PAGE 4096
#define PAGE_ALLIGN( x ) ( PVOID )( (ULONG_PTR)x + ( ( SIZE_OF_PAGE - ( (ULONG_PTR)x & ( SIZE_OF_PAGE - 1 ) ) ) % SIZE_OF_PAGE ) )

// https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/payloads/Demon/include/core/CoffeeLdr.h
#pragma pack(push,1)
typedef struct _SECTION_MAP
{
    PCHAR   Ptr;
    SIZE_T  Size;
} SECTION_MAP, * PSECTION_MAP;
#pragma pack(pop)


#pragma pack(push,1)
typedef struct _COFF_FILE_HEADER
{
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} COFF_FILE_HEADER, * PCOFF_FILE_HEADER;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _COFF_SECTION
{
    CHAR    Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLineNumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;

} COFF_SECTION, * PCOFF_SECTION;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _COFF_RELOC
{
    UINT32  VirtualAddress;
    UINT32  SymbolTableIndex;
    UINT16  Type;
} COFF_RELOC, * PCOFF_RELOC;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _COFF_SYMBOL
{
    union
    {
        CHAR    Name[8];
        UINT32  Value[2];
    } First;

    UINT32 Value;
    UINT16 SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL, * PCOFF_SYMBOL;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct _COFFEE
{
    PVOID             Data;
    PCOFF_FILE_HEADER Header;
    PCOFF_SECTION     Section;
    PCOFF_RELOC       Reloc;
    PCOFF_SYMBOL      Symbol;
    PVOID             ImageBase;
    SIZE_T            BofSize;
    PSECTION_MAP      SecMap;
    PULONG_PTR        GOT;
    SIZE_T            GOTSize;
    PULONG_PTR        BSS;
    SIZE_T            BSSSize;
} COFFEE, * PCOFFEE;
#pragma pack(pop)

