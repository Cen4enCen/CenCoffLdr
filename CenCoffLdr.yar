rule CenCoffLdr
{
    meta:
        author          = "cen4encen"
        description     = "Detect CenCoffLdr"
        arch_context    = "x64"
    
    strings:
		$hex1			= { B9 0D C0 E0 49}
		$hex2			= { B9 B5 9E 96 6B}
		$hex3			= { BA C8 B3 44 C4}
		$hex4 			= { BA 82 FB 03 4C}
		$hex5 			= { BA F0 21 33 FB}
		$hex6 			= { 81 38 05 00 00 C0 [1 - 12] 81 38 94 00 00 C0}
		$str1 			= "Failed To Allocate Beacon Buffer Heap"
		$str2 			= "Buffer size exceeded! Length: %d, Size: %d"
		$str3 			= "Format string can't be NULL"
		$str4 			= "Failed to calculate final string length"
		$str5 			= "Failed to allocate CallbackOutput"
		$str6 			= "Failed to format string. Error code: %d, Error message: %s"
		$str7 			= "received output: "
		$str8 			= "Ldr Resolve Function Successfully"
		$str9 			= "%s C:\\Users\\test\\Desktop\\Harvest.obj entrypoint argumentSize arg1 arg2 ..."
		$str10 			= "BOF Is Not AMD64 :("
		$str11 			= "BOF Total Size %d , GOT Table Size %d , BSS Table Size %d"
		$str12 			= "Virtual Alloc Bof Buffer Failed :("
		$str13 			= "Alloc Bof Buffer Success %p"
		$str14 			= "Process Coff Section Failed :("
		$str15 			= "Process Coffee Section Success"
		$str16 			= "END : \\O/"
		$str17 			= "Failed To Get Param %d,exit ..."
		$str18 			= "NtAllocate Virtual Memory Size %d"
		$str19 			= "Stomping %s %p"
		$str20 			= "Hit Bof Entry %p"
		$str21 			= "Bof Entry Point : %s"
		$str22 			= "Failed To Find Entry Point %s , exit ..."
		$str23 			= "Register Veh Handler ..."
		$str24 			= "Failed To Resolve Symbol %s :("
		$str25 			= "Beacon Symbol %s Not Found :("
		$str26 			= "Oops Bof Caused Exception, Redirecting ... :("
		$str27 			= "Read File Successfully, Size %d"
		
    condition:
        any of them
}
