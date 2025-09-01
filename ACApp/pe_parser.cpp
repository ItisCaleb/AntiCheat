#include "pe_parser.h"
#include <stdexcept>

namespace detail {
	inline DWORD _align(DWORD size, DWORD align, DWORD addr = 0)
	{
		if (!(size % align)) return addr + size;
		return addr + (size / align + 1) * align;
	}
};

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

void PeFile::add_section(const std::string& name, void* data, DWORD size, DWORD characteristics) {
	PIMAGE_NT_HEADERS nt = this->get_nt_header();
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
	int num_sections = nt->FileHeader.NumberOfSections;

	// Calculate new section offsets
	DWORD file_alignment = nt->OptionalHeader.FileAlignment;
	DWORD section_alignment = nt->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER last_section = &sections[num_sections - 1];
	DWORD last_section_end = last_section->PointerToRawData + last_section->SizeOfRawData;
	DWORD new_offset = (last_section_end + file_alignment - 1) / file_alignment * file_alignment;

	// Calculate virtual sizes and RVAs
	DWORD last_rva = detail::_align(last_section->VirtualAddress + last_section->SizeOfRawData, 0x1000);
	printf("last_rva: %llx\n", last_rva);

	// Update NumberOfSections
	nt->FileHeader.NumberOfSections++;
	nt->OptionalHeader.SizeOfImage += size;

	PIMAGE_SECTION_HEADER new_section = &sections[num_sections];
	strncpy((char*)new_section->Name, name.c_str(), 8);
	new_section->Misc.VirtualSize = size;
	new_section->VirtualAddress = last_rva;
	new_section->SizeOfRawData = size;
	new_section->PointerToRawData = new_offset;
	new_section->Characteristics = characteristics;
	
	if (new_offset + size > this->buffer.size()) {
		this->buffer.resize(new_offset + size);
	}
	memcpy(this->buffer.data() + new_offset, data, size);
	
}

void PeFile::save(const std::string& file_name) {
	FILE* f = fopen(file_name.c_str(), "wb");
	fwrite(this->buffer.data(), 1, this->buffer.size(), f);
	fclose(f);
}

std::vector<BYTE>& PeFile::get_buffer() {
	return this->buffer;
}

