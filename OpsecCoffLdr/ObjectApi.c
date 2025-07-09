#include "ObjectApi.h"

HANDLE hProcessHeap = NULL;

COFFAPIFUNC BeaconApi[] =
{
    {.NameHash = BEACONDATAINT_HASH,         .Pointer = BeaconDataInt },
    {.NameHash = BEACONDATAPARSE_HASH,       .Pointer = BeaconDataParse },
    {.NameHash = BEACONDATAEXTRACT_HASH,     .Pointer = BeaconDataExtract },
    {.NameHash = BEACONFORMATALLOC_HASH,     .Pointer = BeaconFormatAlloc },
    {.NameHash = BEACONFORMATFREE_HASH,      .Pointer = BeaconFormatFree },
    {.NameHash = BEACONFORMATINT_HASH,       .Pointer = BeaconFormatInt },
    {.NameHash = BEACONPRINTF_HASH,          .Pointer = BeaconPrintf },
    {.NameHash = BEACONISADMIN_HASH,         .Pointer = BeaconIsAdmin},
    {.NameHash = BEACONOUTPUT_HASH,          .Pointer = BeaconOutput },
    {.NameHash = BEACONDATALENGTH_HASH,      .Pointer = BeaconDataLength },
    {.NameHash = BEACONFORMATPRINTF_HASH,    .Pointer = BeaconFormatPrintf },
    {.NameHash = BEACONFORMATTOSTRING_HASH,  .Pointer = BeaconFormatToString },
    {.NameHash = 0,                          .Pointer = NULL } // end
};

COFFAPIFUNC LdrApi[] =
{
    {.NameHash = TOWIDECHAR_HASH,            .Pointer = toWideChar},
    {.NameHash = FREELIBRARY_HASH,           .Pointer = FreeLibrary},
    {.NameHash = GETMODULEHANDLEA_HASH,      .Pointer = GetModuleHandleA},
    {.NameHash = GETPROCADDRESS_HASH,        .Pointer = GetProcAddress},
    {.NameHash = LOADLIBRARYA_HASH,          .Pointer = LoadLibraryA},
    {.NameHash = CREATETHREAD_HASH,          .Pointer = CreateThread},
    {.NameHash = 0,                          .Pointer = NULL } // end
};

INT BeaconDataInt(PDATA parser)
{
    UINT32 Value = 0;

    if (parser->length < 4) return 0;

    _Memcpy(&Value, parser->buffer + 4, 4);

    parser->buffer += 8;
    parser->length -= 8;

    return (INT)Value;
}


VOID BeaconDataParse(PDATA parser, PCHAR buffer, INT size)
{
    if (parser == NULL)
        return;

    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
}

void BeaconOutput(int type, char* data, int len)
{
    if (data == NULL) return;
    
    char* tempBuffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY ,len + 1);
    if (tempBuffer == NULL)return;  
   
    _Memcpy(tempBuffer, data, len);

    printf("%s", tempBuffer);

    HEAPSECUREFREE(tempBuffer, len);
    return;
}


PCHAR BeaconDataExtract(PDATA parser, PINT size)
{
    INT   Length = 0;
    PVOID Data = NULL;

    if (parser->length < 4) return NULL;

    _Memcpy(&Length, parser->buffer, 4);

    parser->buffer += 4;

    Data = parser->buffer;
    if (Data == NULL)
        return NULL;

    parser->length -= 4;
    parser->length -= Length;
    parser->buffer += Length;

    if (size != NULL) *size = Length;

    return Data;
}


void BeaconFormatAlloc(formatp* format, int maxsz) 
{
    if (format == NULL) return NULL;

    format->original = HeapAlloc(hProcessHeap,0, maxsz);
    if (!format->original)
    {
        printf("Failed To Allocate Beacon Buffer Heap , exit ....");
        exit(0);
    }
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatFree(formatp* format) 
{
    if (format == NULL) return;

    if (format->original)
    {
        HEAPSECUREFREE(format->original,format->length);
        format->original = NULL;
    }

    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}


void BeaconFormatPrintf(formatp* format, char* fmt, ...)
{
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args) ; 
    va_end(args);

    if (format->length + length > format->size) 
    {
        printf("Buffer size exceeded! Length: %d, Size: %d\n", length, format->size);
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length + 1, fmt, args);
    va_end(args);

    format->length += length;
    format->buffer += length; 
}


char* BeaconFormatToString(formatp* format, int* size)
{
    if (size != NULL)
        *size = format->length;

    format->buffer[format->length] = '\0';  
    return format->original;
}


UINT32 swap_endianess(UINT32 indata)
{
    UINT32 testint = 0xaabbccdd;
    UINT32 outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

void BeaconFormatInt(formatp* format, int value)
{
    if (format == NULL)
    {
        return;
    }

    UINT32 indata = value;
    UINT32 outdata = 0;

    if (format->length + 4 > format->size)
    {
        return;
    }

    outdata = swap_endianess(indata);
    _Memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}


VOID BeaconPrintf(INT Type, PCHAR fmt, ...)
{
    va_list     VaListArg = 0;
    PVOID       CallbackOutput = NULL;
    INT         CallbackSize = 0;
    UINT32      RequestID = 0;

    if (!fmt) 
    {
        printf("Format string can't be NULL");
        return;
    }

    va_start(VaListArg, fmt);

    CallbackSize = vsnprintf(NULL, 0, fmt, VaListArg) + 1; // !!! 
    if (CallbackSize < 0) 
    {
        printf("Failed to calculate final string length");
        va_end(VaListArg);
        return;
    }

    CallbackOutput = HeapAlloc(hProcessHeap,0, CallbackSize + 1);
    if (!CallbackOutput)
    {
        printf("Failed to allocate CallbackOutput");
        va_end(VaListArg);
        return;
    }

    if (vsnprintf(CallbackOutput, CallbackSize, fmt, VaListArg) < 0) 
    {
        printf("Failed to format string. Error code: %d, Error message: %s\n", errno, strerror(errno));
        HEAPSECUREFREE(CallbackOutput, CallbackSize);
        va_end(VaListArg);
        return;
    }

    va_end(VaListArg);

    printf("[+] received output: \n%s\n", CallbackOutput);

    HEAPSECUREFREE(CallbackOutput,CallbackSize);
}

// Thread Or ProcessToken
BOOL BeaconIsAdmin(VOID) 
{
    LONG            status = 0; 
    BOOL            bIsadmin        = FALSE;
    TOKEN_ELEVATION Data            = { 0 };
    DWORD           dwSize          = sizeof(TOKEN_ELEVATION);
    HANDLE          hToken          = 0;
    
    // if impersonating  we use thread token 
    win32Api.pfnNtOpenThreadToken(((HANDLE)(LONG_PTR) - 2), TOKEN_QUERY, TRUE, &hToken);
  
    // else we use process token 
    if(!hToken)  win32Api.pfnNtOpenProcessToken(((HANDLE)(LONG_PTR)-1), TOKEN_QUERY, &hToken);

    if (!win32Api.pfnNtQueryInformationToken(hToken, TokenElevation, &Data, dwSize, &dwSize))
    {
        bIsadmin = Data.TokenIsElevated;
    }

    return bIsadmin;
}


int BeaconDataLength(datap* parser) 
{
    if (parser == NULL) return 0;
    return parser->length;
}


BOOL toWideChar(char* src, wchar_t* dst, int max) 
{
    if (max < sizeof(wchar_t))
        return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, src, -1, dst, max / sizeof(wchar_t));
}