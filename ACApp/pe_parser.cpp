#include "pe_parser.h"
#include <stdexcept>

PeFile::PeFile(const std::string &file_name){
	FILE* f = fopen(file_name.c_str(), "rb");
	if (!f) {
		throw std::runtime_error("Can't open executable");
	}
	fseek(f, 0L, SEEK_END);
	uint64_t fsize = ftell(f);
	fseek(f, 0L, SEEK_SET);
	printf("file size: %lld\n", fsize);
	this->buffer.resize(fsize);
	fread(this->buffer.data(), 1, fsize, f);
	fclose(f);

	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->buffer.data());
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		throw std::runtime_error("Invalid Signature");

	}
}

PeFile::PeFile(void* ptr, DWORD size) {
	this->buffer.resize(size);
	memcpy(this->buffer.data(), ptr, size);

	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->buffer.data());
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		throw std::runtime_error("Invalid Signature");
	}
}
PeFile::~PeFile() {


}
PIMAGE_DOS_HEADER PeFile::get_dos_header() {
	return reinterpret_cast<PIMAGE_DOS_HEADER>(this->buffer.data());
}
PIMAGE_NT_HEADERS PeFile::get_nt_header() {
	return reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer.data() + get_dos_header()->e_lfanew);
}

PIMAGE_SECTION_HEADER PeFile::get_section(const std::string& section_name) {
	auto nt_header = get_nt_header();
	PIMAGE_FILE_HEADER file_header = &nt_header->FileHeader;

	PIMAGE_SECTION_HEADER sec_header = IMAGE_FIRST_SECTION(nt_header);
	bool found = false;
	for (int i = 0; i < file_header->NumberOfSections; i++) {

		if (strncmp(reinterpret_cast<char*>(sec_header->Name), section_name.c_str(), section_name.size()) == 0) {
			return sec_header;
		}
		sec_header++;
	}
	return nullptr;
}