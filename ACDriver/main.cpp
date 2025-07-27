#include <ntifs.h>

void debug_print(PCSTR text) {
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}

NTSTATUS DriverEntry() {
	debug_print("test");
	return STATUS_SUCCESS;
}