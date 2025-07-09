#include "Utils.h"

BOOL IsDigit(char * str)
{
    if (str == NULL || *str == '\0') return 0;

    if (*str == '-') str++;


    while (*str) {
        if (!isdigit(*str)) 
        {
            return FALSE; 
        }
        str++;
    }

    return TRUE;  // 如果全部是数字，则返回1

}

wchar_t* GetDllName(const wchar_t* fullDllName)
{
    const wchar_t* pszTempDllName = fullDllName;
    wchar_t* pszDllName = (wchar_t*)fullDllName;

    while (*pszTempDllName++) {}

    while (--pszTempDllName >= fullDllName)
    {
        if (*pszTempDllName == L'\\') {
            pszDllName = (wchar_t*)pszTempDllName + 1;
            break;
        }
    }

    return pszDllName;
}

BOOL _Memcpy(void* dest, void* src, size_t size) 
{
    if (dest == NULL || src == NULL)
    {
        return FALSE;
    }
    char* csrc = (char*)src;
    char* cdest = (char*)dest;
    for (size_t i = 0; i < size; i++) 
    {
        cdest[i] = csrc[i];
    }
    return TRUE;
}


PVOID _Memset(void* dest, int ch, size_t count)
{
    unsigned char* p = (unsigned char*)dest;
    unsigned char value = (unsigned char)ch;

    for (size_t i = 0; i < count; i++) 
    {
        p[i] = value;
    }

    return dest;
}

SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    if (String == NULL)
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

INT _Strcmp(unsigned char* a, unsigned char* b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}


SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    if (String == NULL)
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}



VOID _RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    if (SourceString == NULL) {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
    else {
        size_t size = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)size;
        DestinationString->MaximumLength = (USHORT)(size + sizeof(WCHAR));
        DestinationString->Buffer = (PWSTR)SourceString;
    }
}

// Havoc C2
ULONG HashEx(PVOID String,ULONG Length,BOOL Upper)
{
    ULONG  Hash = HASH_KEY;
    PUCHAR Ptr = String;

    if (!String) 
    {
        return 0;
    }

    do 
    {
        UCHAR character = *Ptr;

        if (!Length) {
            if (!*Ptr) {
                break;
            }
        }
        else
        {
            if ((ULONG)(Ptr - String) >= Length) 
            {
                break;
            }

            if (!*Ptr)
            {
                ++Ptr;
            }
        }

        if (Upper) 
        {
            if (character >= 'a')
            {
                character -= 0x20;
            }
        }

        Hash = ((Hash << 7) + Hash) + character;

        ++Ptr;
    } while (TRUE);

    return Hash;
}

PCHAR StringTokenA(PCHAR String, CONST PCHAR Delim)
{
    PCHAR SpanP, Token;
    INT C, SC;
    PCHAR CopyString;

    if (String == NULL)
        return NULL;

    CopyString = _strdup(String); 
    if (CopyString == NULL)
        return NULL; 

CONTINUE:

    C = *CopyString++;

    for (SpanP = (PCHAR)Delim; (SC = *SpanP++) != ERROR_SUCCESS;)
    {
        if (C == SC)
            goto CONTINUE;  
    }

    if (C == ERROR_SUCCESS)
        return NULL;  

    Token = CopyString - 1;  

    for (;;)
    {
        C = *CopyString++;
        SpanP = (PCHAR)Delim;

        do {
            if ((SC = *SpanP++) == C)
            {
                if (C == ERROR_SUCCESS)
                    CopyString = NULL;
                else
                    CopyString[-1] = '\0';  

                return Token;
            }
        } while (SC != ERROR_SUCCESS);
    }

    return NULL;
}

// BokuLoader 
VOID utf16_to_utf8(wchar_t* wide_string, DWORD wide_string_len, BYTE* ascii_string)
{
    for (DWORD i = 0; i < wide_string_len; ++i)
    {
        wchar_t this_char = wide_string[i];
        *ascii_string++ = (BYTE)this_char;
    }
    *ascii_string = '\0';
}