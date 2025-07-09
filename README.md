# CenCoffLdr

A parser for COFF files.

## Features

### 1. BSS Table Parsing

When we use MSVC for BOF development (especially if we have uninitialized global variables),there is no .bss section, which is different from MINGW.

![MSVC](.\Img\MSVC.png) 

<img src=".\Img\MINGW.png" alt="MINGW" style="zoom:67%;" /> 

In MINGW, everything works fine when we define uninitialized global variables in BOFs. However, when compiled with MSVC, things changes. I compared several C2 frameworks, and the results were as follows:

- **CobaltStrike** -> Unable to resolve symbols.

![CobaltStrike-bss-msvc](.\img.\CobaltStrike-bss-msvc.png)  

- **Havoc** -> Beacon crashes without any specific settings (I noticed your VEH implementation).

![Havoc-bss-msvc](.\Img\Havoc-bss-msvc.png)

- **BRC4** -> No crash, but no output. 

![BRC4-bss-msvc](.\Img\BRC4-bss-msvc.png) 

But there is no denying the fact that BRC4, CobaltStrike, and Havoc are outstanding C2 frameworks ！！！

![look](D:\Evasion\Github\CenCoffLdr\Img\look.png) 

After parsing the BSS Table, BOFs run perfectly regardless of whether it is compiled with MSVC or MINGW.

 <img src=".\Img\cenCoffLdr-bss-MSVC-MINGW.png" alt="cenCoffLdr-bss-MSVC-MINGW" style="zoom:80%;" />



### 2. Exception Caught

Add VEH (Vectored Exception Handler) captures exceptions, but skip 0xE06D7363 exception. I found that this exception was triggered while running the following BOF, but it didn't require any handling, and the BOF ran perfectly:

```
https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Askcreds/SOURCE/Askcreds.c
```

![0xE06D7363](.\Img\0xE06D7363.png)

### 3. Opsec Enhancements

The BOF parser allows you to use ModuleStomping Or VirtualAlloc without creating RWX (Read/Write/Execute) memory regions.

And of course You can replace `NtApi` calls with `Syscall`, `Spoofcall`, `Proxycall`, etc., if needed.

More Opsec techniques can be added by the user depending on their needs.

### 4. Parameter Parsing

CobaltStrike BOF parameter parsing follows a specific format:

```
${totalLength}${stringArgumentLength}${stringArgument}${intArgument} .... 
```

I modified the parser to use the following format, with corresponding parsing functions adjusted accordingly:

```
{TotalSize}{Arg1Size}{Arg1}{Arg2Size}{Arg2} .... 
```

### 5. Slot Issues? No!

In CobaltStrike, the size of the GOT (Global Offset Table) is pre-defined. When too many APIs are called by the BOF, the following message appears (CS 4.9.1):

![Slot](.\Img\Slot.png)  

The corresponding code (open source implementation) is as follows. When the `index` exceeds `MAX_DYNAMIC_FUNCS`, the "No Slot" message is triggered:

<img src=".\Img\slot1.png" alt="slot1" style="zoom:80%;" /> 

The solution is to dynamically allocate memory for the GOT, rather than using a hard-coded approach.

------

## TODO

- Add Unicode parsing support in the `BofPack` function.

------

## Credits

- [Otterhacker - CoffLoader](https://otterhacker.github.io/Malware/CoffLoader.html)
- [HavocFramework - CoffeeLdr](https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/CoffeeLdr.c)

