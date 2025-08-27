#include <Windows.h>
#include <stdio.h>
#include "lazy_importer.h"


extern "C" void ac_load() {
	auto msvcrtLib = LI_FN(LoadLibraryA)("msvcrt.dll");
	LI_FN(printf).in(msvcrtLib)("Hello world!");


}