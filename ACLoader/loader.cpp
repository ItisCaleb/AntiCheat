#include <Windows.h>
#include <stdio.h>
#include "lazy_importer.h"

#pragma comment(linker, "/merge:.rdata=.text")
const volatile DWORD oep = 0xdeadbabe;
extern "C" void ac_load() {

	
	auto msvcrtLib = LI_FN(LoadLibraryA)("msvcrt.dll");
	
	auto printf_f = LI_FN(printf).in(msvcrtLib);
	auto base = LI_FN(GetModuleHandleA)((LPCSTR)NULL);
	printf_f("Loading! Base at '0x%llx'\n", (ULONGLONG)base);
	((void (*)())((ULONGLONG)base + oep))();
}
