#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "LdrFuncResolve.h"

// Beacon Hash
#define BEACONOUTPUT_HASH          0xfc876ee8
#define BEACONPRINTF_HASH          0x1adc984a
#define BEACONDATAINT_HASH         0x796cca7c
#define BEACONISADMIN_HASH         0xa34b467c
#define BEACONDATAPARSE_HASH       0x8ab6b94c
#define BEACONFORMATINT_HASH       0x3b629d6b
#define BEACONFORMATFREE_HASH      0xec500b42
#define BEACONDATALENGTH_HASH      0xe2895333
#define BEACONDATAEXTRACT_HASH     0xf1f4ceac
#define BEACONFORMATALLOC_HASH     0xc10b65ab
#define BEACONFORMATPRINTF_HASH    0x6c4a7033
#define BEACONFORMATTOSTRING_HASH  0xb3e274fa

// LdrHash
#define TOWIDECHAR_HASH           0x30a85679
#define FREELIBRARY_HASH          0x2adb73e6
#define LOADLIBRARYA_HASH         0x365b2325
#define CREATETHREAD_HASH         0x2faad03b
#define GETPROCADDRESS_HASH       0x8f092309
#define GETMODULEHANDLEA_HASH     0x41b97c22


#pragma pack(push,1)
typedef struct
{
    UINT_PTR    NameHash;
    PVOID       Pointer;
} COFFAPIFUNC;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct {
    PCHAR  original;
    PCHAR  buffer;  
    INT    length;  
    INT    size;    
} datap, * PDATA, * PFORMAT;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct {
    char* original; 
    char* buffer;   
    int    length;  
    int    size;    
} formatp;
#pragma pack(pop)

INT BeaconDataInt(PDATA parser);
int BeaconDataLength(datap* parser);
void BeaconFormatFree(formatp* format);
VOID BeaconPrintf(INT Type, PCHAR fmt, ...);
PCHAR BeaconDataExtract(PDATA parser, PINT size);
BOOL toWideChar(char* src, wchar_t* dst, int max);
void BeaconFormatAlloc(formatp* format, int maxsz);
void BeaconFormatInt(formatp* format, int value);
char* BeaconFormatToString(formatp* format, int* size);
VOID BeaconFormatPrintf(PFORMAT format, char* fmt, ...);
VOID BeaconDataParse(PDATA parser, PCHAR buffer, INT size);
void BeaconOutput(int type, char* data, int len);
BOOL BeaconIsAdmin(VOID);
extern COFFAPIFUNC  BeaconApi[];
extern COFFAPIFUNC  LdrApi[];
extern HANDLE       hProcessHeap;

#define HEAPSECUREFREE(pBuffer, size) \
    if (pBuffer) { \
        _Memset(pBuffer, 0, size);  /* Çå¿ÕÄÚ´æ */ \
        HeapFree(hProcessHeap, 0, pBuffer);  /* ÊÍ·ÅÄÚ´æ */ \
        pBuffer = NULL;  /* ·ÀÖ¹Ðü¹ÒÖ¸Õë */ \
    }
