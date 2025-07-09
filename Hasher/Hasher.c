#include <Windows.h>
#include <stdio.h>

#define HASH_KEY 5391
#define SEED	 0xEDB88870

ULONG HashEx(PVOID String, ULONG Length, BOOL Upper);
unsigned int crc32a(char* str);

int main()
{
    char* testStr = "NtOpenProcessToken";
    printf("HashEx : %lx\n", HashEx(testStr, strlen(testStr), FALSE));
    printf("Crc32  : %lx\n", crc32a(testStr));
    return 0;
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


ULONG HashEx(PVOID String, ULONG Length, BOOL Upper)
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