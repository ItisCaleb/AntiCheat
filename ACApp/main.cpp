#include <stdio.h>
//#include "anti_cheat.h"
#include <stdint.h>
#include <Windows.h>
#include "pe_parser.h"

void* find_signature(void* data, DWORD size, DWORD signature){
    for (DWORD i = 0; i < size / sizeof(DWORD); i++) {
        if (memcmp((DWORD*)data + i, &signature, sizeof(DWORD)) == 0) {
            return (void*)((DWORD*)data + i);
        }
    }
    return nullptr;
}

int main() {
	PeFile f("../a.exe");
	auto text_sec = f.get_section(".text");

	DWORD orignal_oep = f.get_nt_header()->OptionalHeader.AddressOfEntryPoint;


    PeFile loader("../x64/Release/ACLoader.exe");
    auto loader_text_sec = loader.get_section(".text");
    f.add_section(".stub", loader.get_buffer().data() + loader_text_sec->PointerToRawData,
        loader_text_sec->SizeOfRawData,
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);
	auto stub_sec = f.get_section(".stub");
    f.get_nt_header()->OptionalHeader.AddressOfEntryPoint = stub_sec->VirtualAddress +
        loader.get_nt_header()->OptionalHeader.AddressOfEntryPoint - loader.get_nt_header()->OptionalHeader.BaseOfCode;
    auto oep_sig = find_signature(&f.get_buffer()[stub_sec->PointerToRawData], stub_sec->SizeOfRawData, 0xdeadbabe);
    if (!oep_sig) {
        printf("Can't find oep signature\n");
    }
    else {
        printf("Patching oep\n");
        printf("Original oep: 0x%llx\n", orignal_oep);
        *(DWORD*)oep_sig = orignal_oep;
    }

	f.save("a.packed.exe");
	return 0;
}