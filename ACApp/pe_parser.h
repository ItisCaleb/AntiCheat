#pragma once
#include <string>
#include <vector>
#include <Windows.h>


class PeFile {
public:
	PeFile(const std::string &file_name);
	PeFile(void* ptr, DWORD size);
	~PeFile();
	PIMAGE_DOS_HEADER get_dos_header();
	PIMAGE_NT_HEADERS get_nt_header();

	PIMAGE_SECTION_HEADER get_section(const std::string &section_name);
	std::vector<BYTE>& get_buffer();
	void add_section(const std::string &name, void *data, DWORD size, DWORD characteristics);
	void save(const std::string& file_name);
private:
	std::vector<BYTE> buffer;
};