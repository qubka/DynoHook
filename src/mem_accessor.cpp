#include <dynohook/core.h>
#include <dynohook/mem_accessor.h>
#include <dynohook/mem_protector.h>
#include <dynohook/os.h>

#include <cstring>

using namespace dyno;

#if DYNO_PLATFORM_WINDOWS

bool MemAccessor::mem_copy(uintptr_t dest, uintptr_t src, size_t size) const {
	std::memcpy((char*)dest, (char*)src, (SIZE_T)size);
	return true;
}

bool MemAccessor::safe_mem_write(uintptr_t dest, uintptr_t src, size_t size, size_t& written) const noexcept {
	written = 0;
	return WriteProcessMemory(GetCurrentProcess(), (char*)dest, (char*)src, (SIZE_T)size, (PSIZE_T)&written);
}

bool MemAccessor::safe_mem_read(uintptr_t src, uintptr_t dest, size_t size, size_t& read) const noexcept {
	HANDLE process = GetCurrentProcess();
	read = 0;

	if (ReadProcessMemory(process, (char*)src, (char*)dest, (SIZE_T)size, (PSIZE_T)&read) && read > 0)
		return true;

	// Tries to read again on a partial copy, but limited by the end of the memory region
	if (GetLastError() == ERROR_PARTIAL_COPY) {
		MEMORY_BASIC_INFORMATION info;
		if (VirtualQueryEx(process, (char*)src, &info, sizeof(info)) != 0) {
			uintptr_t end = (uintptr_t)info.BaseAddress + info.RegionSize;
			if (src + size > end)
				return ReadProcessMemory(process, (char*)src, (char*)dest, (SIZE_T)(end - src), (PSIZE_T)&read) && read > 0;
		}
	}
	return false;
}

ProtFlag MemAccessor::mem_protect(uintptr_t dest, size_t size, ProtFlag prot, bool& status) const {
	DWORD orig;
	status = VirtualProtect((char*)dest, (SIZE_T)size, TranslateProtection(prot), &orig) != 0;
	return TranslateProtection((int)orig);
}

#elif DYNO_PLATFORM_LINUX

#include <fstream>

struct region_t {
	uintptr_t start;
	uintptr_t end;
	ProtFlag prot;
};

static region_t get_region_from_addr(uintptr_t addr) {
	region_t res{};

	std::ifstream f("/proc/self/maps");
	std::string s;
	while (std::getline(f, s)) {
		if (!s.empty() && s.find("vdso") == std::string::npos && s.find("vsyscall") == std::string::npos) {
			char* strend = &s[0];
			uintptr_t start = strtoul(strend  , &strend, 16);
			uintptr_t end   = strtoul(strend+1, &strend, 16);
			if (start != 0 && end != 0 && start <= addr && addr < end) {
				res.start = start;
				res.end = end;

				++strend;
				if (strend[0] == 'r')
					res.prot = res.prot | ProtFlag::R;
	
				if (strend[1] == 'w')
					res.prot = res.prot | ProtFlag::W;
	
				if (strend[2] == 'x')
					res.prot = res.prot | ProtFlag::X;

				if (res.prot == ProtFlag::UNSET)
					res.prot = ProtFlag::N;

				break;
			}
		}
	}
	return res;
}

bool MemAccessor::mem_copy(uintptr_t dest, uintptr_t src, size_t size) const {
	std::memcpy((char*)dest, (char*)src, (size_t)size);
	return true;
}

bool MemAccessor::safe_mem_write(uintptr_t dest, uintptr_t src, size_t size, size_t& written) const noexcept {
	region_t region_infos = get_region_from_addr(src);
	
	// Make sure that the region we query is writable
	if (!(region_infos.prot & ProtFlag::W))
		return false;
	
	size = std::min<uintptr_t>(region_infos.end - src, size);
	
	std::memcpy((void*)dest, (void*)src, (size_t)size);
	written = size;

	return true;
}

bool MemAccessor::safe_mem_read(uintptr_t src, uintptr_t dest, size_t size, size_t& read) const noexcept {
	region_t region_infos = get_region_from_addr(src);
	
	// Make sure that the region we query is readable
	if (!(region_infos.prot & ProtFlag::R))
		return false;

	size = std::min<uintptr_t>(region_infos.end - src, size);

	std::memcpy((void*)dest, (void*)src, (size_t)size);
	read = size;

	return true;
}

ProtFlag MemAccessor::mem_protect(uintptr_t dest, size_t size, ProtFlag prot, bool& status) const {
	region_t region_infos = get_region_from_addr(dest);
	uintptr_t aligned_dest = MEMORY_ROUND(dest, getPageSize());
	uintptr_t aligned_size = MEMORY_ROUND_UP(size, getPageSize());
	status = mprotect((void*)aligned_dest, aligned_size, TranslateProtection(prot)) == 0;
	return region_infos.prot;
}

#elif DYNO_PLATFORM_APPLE

bool MemAccessor::mem_copy(uintptr_t dest, uintptr_t src, size_t size) const {
	std::memcpy((char*)dest, (char*)src, (size_t)size);
	return true;
}

bool MemAccessor::safe_mem_write(uintptr_t dest, uintptr_t src, size_t size, size_t& written) const noexcept {
	bool res = std::memcpy((void*)dest, (void*)src, (size_t)size) != nullptr;
	if (res)
		written = size;
	else
		written = 0;

	return res;
}

bool MemAccessor::safe_mem_read(uintptr_t src, uintptr_t dest, size_t size, size_t& read) const noexcept {
	bool res = std::memcpy((void*)dest, (void*)src, (size_t)size) != nullptr;
	if (res)
		read = size;
	else
		read = 0;

	return res;
}

ProtFlag MemAccessor::mem_protect(uintptr_t dest, size_t size, ProtFlag prot, bool& status) const {
	status = mach_vm_protect(mach_task_self(), (mach_vm_address_t)MEMORY_ROUND(dest, getPageSize()), (mach_vm_size_t)MEMORY_ROUND_UP(size, getPageSize()), FALSE, TranslateProtection(prot)) == KERN_SUCCESS;
	return ProtFlag::R | ProtFlag::X;
}

#endif

/**
 * Write a 14 byte indirect near jump.
 */
insts_t MemAccessor::makex64Jump(uintptr_t address, uintptr_t destination) {
	std::vector<uint8_t> bytes(14);
	bytes[0] = 0xFF;
	bytes[1] = 0x25;
	std::memcpy(&bytes[6], &destination, 8);

	return { Instruction(this, address, Instruction::Displacement{0}, 0, false, false, std::move(bytes), "jmp", int_to_hex(destination), Mode::x64) };
}

/**
 * Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
 * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.
 */
insts_t MemAccessor::makex64PreferredJump(uintptr_t address, uintptr_t destination) {
	Instruction::Displacement zeroDisp{0};
	uintptr_t curInstAddress = address;

	std::vector<uint8_t> raxBytes = { 0x50 };
	Instruction pushRax(this,
						curInstAddress,
						zeroDisp,
						0,
						false,
						false,
						std::move(raxBytes),
						"push",
						"rax", Mode::x64);
	curInstAddress += pushRax.size();

	std::stringstream ss;
	ss << std::hex << destination;

	std::vector<uint8_t> movRaxBytes(10);
	movRaxBytes[0] = 0x48;
	movRaxBytes[1] = 0xB8;
	std::memcpy(&movRaxBytes[2], &destination, 8);

	Instruction movRax(this, curInstAddress, zeroDisp, 0, false, false,
					   std::move(movRaxBytes), "mov", "rax, " + ss.str(), Mode::x64);
	curInstAddress += movRax.size();

	std::vector<uint8_t> xchgBytes = { 0x48, 0x87, 0x04, 0x24 };
	Instruction xchgRspRax(this, curInstAddress, zeroDisp, 0, false, false,
						   std::move(xchgBytes), "xchg", "QWORD PTR [rsp],rax", Mode::x64);
	curInstAddress += xchgRspRax.size();

	std::vector<uint8_t> retBytes = { 0xC3 };
	Instruction ret(this, curInstAddress, zeroDisp, 0, false, false,
					std::move(retBytes), "ret", "", Mode::x64);

	return { pushRax, movRax, xchgRspRax, ret };
}

/**
 * Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
 * destHolder should point to the memory location that *CONTAINS* the address to be jumped to.
 * Destination should be the value that is written into destHolder, and be the address of where
 * the jmp should land.
 */
insts_t MemAccessor::makex64MinimumJump(uintptr_t address, uintptr_t destination, uintptr_t destHolder) {
	Instruction::Displacement disp{0};
	disp.Relative = Instruction::calculateRelativeDisplacement<int32_t>(address, destHolder, 6);

	std::vector<uint8_t> destBytes(8);
	std::memcpy(destBytes.data(), &destination, 8);
	Instruction specialDest(this, destHolder, disp, 0, false, false, std::move(destBytes), "dest holder", "", Mode::x64);

	std::vector<uint8_t> bytes(6);
	bytes[0] = 0xFF;
	bytes[1] = 0x25;
	std::memcpy(&bytes[2], &disp.Relative, 4);

	std::stringstream ss;
	ss << std::hex << "[" << destHolder << "] ->" << destination;

	return { specialDest, Instruction(this, address, disp, 2, true, true, std::move(bytes), "jmp", ss.str(), Mode::x64) };
}

insts_t MemAccessor::makex86Jmp(uintptr_t address, uintptr_t destination) {
	Instruction::Displacement disp{0};
	disp.Relative = Instruction::calculateRelativeDisplacement<int32_t>(address, destination, 5);

	std::vector<uint8_t> bytes(5);
	bytes[0] = 0xE9;
	std::memcpy(&bytes[1], &disp.Relative, 4);

	return { Instruction(this, address, disp, 1, true, false, std::move(bytes), "jmp", int_to_hex(destination), Mode::x86) };
}

insts_t MemAccessor::makeAgnosticJmp(uintptr_t address, uintptr_t destination) {
#if DYNO_ARCH_X86 == 32
	return makex86Jmp(address, destination);
#elif DYNO_ARCH_X86 == 64
	return makex64PreferredJump(address, destination);
#endif
}

insts_t MemAccessor::makex64DestHolder(uintptr_t destination, uintptr_t destHolder) {
	std::vector<uint8_t> destBytes(8);
	std::memcpy(destBytes.data(), &destination, 8);
	return insts_t{ Instruction(this, destHolder, Instruction::Displacement{0}, 0, false, false, std::move(destBytes), "dest holder", "", Mode::x64) };
}

void MemAccessor::writeEncoding(const insts_t& instructions) {
	for (const auto& inst : instructions)
		writeEncoding(inst);
}

/**
 * Write the raw bytes of the given instruction into the memory specified by the
 * instruction's address. If the address value of the instruction has been changed
 * since the time it was decoded this will copy the instruction to a new memory address.
 * This will not automatically do any code relocation, all relocation logic should
 * first modify the byte array, and then call write encoding, proper order to relocate
 * an instruction should be disasm instructions -> set relative/absolute displacement() ->
 */
void MemAccessor::writeEncoding(const Instruction& instruction) {
	assert(instruction.size() <= instruction.getBytes().size());
	mem_copy(instruction.getAddress(), (uintptr_t)&instruction.getBytes()[0], instruction.size());
}
