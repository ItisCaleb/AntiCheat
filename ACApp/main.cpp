#include <stdio.h>
#include "anti_cheat.h"
#include <stdint.h>
#include <Windows.h>
#include "pe_parser.h"

namespace detail {
	static DWORD align(DWORD size, DWORD align, DWORD addr) {
		if (size % align == 0) return addr + size;
		return addr + ((size / align) + 1) * align;
	}
}

void get_loader_code() {

}


int main() {
	PeFile f("./a.exe");
	auto text_sec = f.get_section(".text");
	printf("RVA : 0x%llx\n", text_sec->VirtualAddress);
	printf("VirtualSize : 0x%llx\n", text_sec->Misc.VirtualSize);
	printf("PointerToRawData : 0x%llx\n", text_sec->PointerToRawData);
	printf("SizeOfRawData : 0x%llx\n", text_sec->SizeOfRawData);

	return 0;
}