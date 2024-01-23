#include <dynohook/core.h>
#include <dynohook/os.h>

namespace dyno {

uintptr_t findPattern(uintptr_t rangeStart, size_t len, const char* pattern) {
	unsigned char pattern_scratch[FINDPATTERN_SCRATCH_SIZE] = { 0 };
	unsigned char mask_scratch[FINDPATTERN_SCRATCH_SIZE] = { 0 };
	const size_t patSize = getPatternSize(pattern);
	char* pat = (char*)&pattern_scratch[0];
	char* msk = (char*)&mask_scratch[0];

	if (patSize + 1 > len)
		return 0;

	size_t counter = patSize;
	while (counter) {
		if (*(uint8_t*)pattern == (uint8_t)'\?') {
			*pat++ = 0;
			*msk++ = '?';
		} else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
		}
		pattern += 3;
		counter--;
	}

	*msk = 0;
	for (size_t n = 0; n < (len - (patSize + 1)); n++) {
		if (isMatch((char*)(rangeStart + n), (char*)(&pattern_scratch[0]), (char*)(&mask_scratch[0]))) {
			return rangeStart + n;
		}
	}
	return 0;
}

size_t getPatternSize(const char* pattern) {
	const size_t l = strlen(pattern);

	// c = 2 * b + (b - 1) . 2 chars per byte + b - 1 spaces between
	return (l + 1) / 3;
}

uintptr_t findPattern_rev(uintptr_t rangeStart, size_t len, const char* pattern) {
	unsigned char pattern_scratch[FINDPATTERN_SCRATCH_SIZE] = { 0 };
	unsigned char mask_scratch[FINDPATTERN_SCRATCH_SIZE] = { 0 };
	const size_t patSize = getPatternSize(pattern);
	char* pat = (char*)&pattern_scratch[0];
	char* msk = (char*)&mask_scratch[0];

	if (patSize + 1 > len)
		return 0;

	size_t counter = patSize;
	while (counter) {
		if (*(uint8_t*)pattern == (uint8_t)'\?') {
			*pat++ = 0;
			*msk++ = '?';
		} else {
			*pat++ = getByte(pattern);
			*msk++ = 'x';
		}
		pattern += 3;
		counter--;
	}

	*msk = 0;
	for (size_t n = len - (patSize + 1); n > 0; n--) {
		if (isMatch((char*)(rangeStart + n), (char*)(&pattern_scratch[0]), (char*)(&mask_scratch[0]))) {
			return rangeStart + n;
		}
	}
	return 0;
}

#if DYNO_ARCH_X86 == 64
uint64_t calc_2gb_below(uint64_t address) {
	return (address > (uint64_t)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

uint64_t calc_2gb_above(uint64_t address) {
	return (address < (uint64_t)0xffffffff80000000) ? address + 0x7ff80000 : (uint64_t)0xfffffffffff80000;
}
#endif

#if DYNO_PLATFORM_WINDOWS

bool boundedAllocSupported() {
	auto hMod = LoadLibraryA("kernelbase.dll");
	if (hMod == NULL)
		return false;

	return GetProcAddress(hMod, "VirtualAlloc2") != NULL;
}

uintptr_t boundAlloc(uintptr_t min, uintptr_t max, size_t size) {
	MEM_ADDRESS_REQUIREMENTS addressReqs = { 0 };
	MEM_EXTENDED_PARAMETER param = { 0 };

	SYSTEM_INFO info = { 0 };
	GetSystemInfo(&info);

	addressReqs.Alignment = 0; // any alignment
	addressReqs.LowestStartingAddress = (PVOID)min < info.lpMinimumApplicationAddress ? info.lpMinimumApplicationAddress : (PVOID)min; // PAGE_SIZE aligned
	addressReqs.HighestEndingAddress = (PVOID)(max - 1) > info.lpMaximumApplicationAddress ? info.lpMaximumApplicationAddress : (PVOID)(max - 1); // PAGE_SIZE aligned, exclusive so -1

	param.Type = MemExtendedParameterAddressRequirements;
	param.Pointer = &addressReqs;

	auto hMod = LoadLibraryA("kernelbase.dll");
	if (hMod == NULL)
		return false;

	auto pVirtualAlloc2 = (decltype(&::VirtualAlloc2))GetProcAddress(hMod, "VirtualAlloc2");
	return (uintptr_t)pVirtualAlloc2(
		GetCurrentProcess(), (PVOID)NULL,
		(SIZE_T)size,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE,
		&param, 1);
}

uintptr_t boundAllocLegacy(uintptr_t start, uintptr_t end, size_t size) {
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(si));
	GetSystemInfo(&si);

	// start low, go up
	MEMORY_BASIC_INFORMATION mbi;
	for (uintptr_t addr = start; addr < end;) {
		if (!VirtualQuery((char*)addr, &mbi, sizeof(mbi)))
			return 0;

		assert(mbi.RegionSize != 0);
		if (mbi.State != MEM_FREE || mbi.RegionSize < size) {
			addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
			continue;
		}

		uintptr_t nextPage = AlignUpwards((uintptr_t)mbi.BaseAddress, si.dwAllocationGranularity);
		
		if (auto allocated = (uintptr_t)VirtualAlloc((char*)nextPage, (SIZE_T)size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
			return allocated;
		} else if (GetLastError() == ERROR_DYNAMIC_CODE_BLOCKED) {
			addr += size;
		} else {
			addr = nextPage + mbi.RegionSize;
		}
	}
	return 0;
}

void boundAllocFree(uintptr_t address, size_t size) {
	(void)size;
	VirtualFree((LPVOID)address, (SIZE_T)0, MEM_RELEASE);
}

size_t getAllocationAlignment() {
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(si));
	GetSystemInfo(&si);
	return si.dwAllocationGranularity;
}

size_t getPageSize() {
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	return static_cast<size_t>(sysInfo.dwPageSize);
}

#elif DYNO_PLATFORM_LINUX

bool boundedAllocSupported() {
	return true;
}

uintptr_t boundAlloc(uintptr_t min, uintptr_t max, size_t size) {
	return boundAllocLegacy(min, max, size);
}

uintptr_t boundAllocLegacy(uintptr_t start, uintptr_t end, size_t size) {
	void* hint = (void*)((end - 1) / 2 + start / 2);
	uintptr_t res = (uintptr_t)mmap(hint, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (res == (uintptr_t)MAP_FAILED)
		return 0;

	if (res < start || res >= end) {
		boundAllocFree(res, size);
		return 0;
	}

	return res;
}

void boundAllocFree(uintptr_t address, size_t size) {
	munmap((void*)address, size);
}

size_t getAllocationAlignment() {
/*
From malloc-internal.h and malloc-alignment.h

#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif
// The corresponding word size. 
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
						  ? __alignof__ (long double) : 2 * SIZE_SZ)
*/
	//return (2 * sizeof(size_t) < __alignof__ (long double) ? __alignof__ (long double) : 2 * sizeof(size_t));

	return getPageSize();
}

size_t getPageSize() {
	return static_cast<size_t>(sysconf(_SC_PAGESIZE));
}
#elif DYNO_PLATFORM_APPLE

bool boundedAllocSupported() {
	return false;
}

uintptr_t boundAlloc(uintptr_t min, uintptr_t max, size_t size) {
	return boundAllocLegacy(min, max, size);
}

uintptr_t boundAllocLegacy(uintptr_t start, uintptr_t end, size_t size) {
	// VM_FLAGS_ANYWHERE allows for better compatibility as the Kernel will find a place for us.
	//int flags = (address_hint == nullptr ? VM_FLAGS_ANYWHERE : VM_FLAGS_FIXED);
	int flags = VM_FLAGS_FIXED;

	uintptr_t increment = getAllocationAlignment();
	for (uintptr_t address = start; address < (end - 1); address += increment) {
		void* res = (void*)address;
		if (mach_vm_allocate(task, &res, (mach_vm_size_t)size, flags) == KERN_SUCCESS) {
			address = (uintptr_t)res;
			if (address >= start && address < end)
				return address;

			boundAllocFree(address, size);
		}
	}
	
	return 0;
}

void boundAllocFree(uintptr_t address, size_t size) {
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)address, (mach_vm_size_t)size);
}

size_t getAllocationAlignment() {
	return getPageSize();
}

size_t getPageSize() {
	return static_cast<size_t>(sysconf(_SC_PAGESIZE));
}

#endif
}