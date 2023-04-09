#include "utilities.hpp"

#include "capstone/capstone.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <climits>
#define PAGE_EXECUTE_READWRITE (PROT_READ | PROT_WRITE | PROT_EXEC)
#endif

// From: http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html

void* AllocateMemory(void* addr, size_t size) {
#ifdef _WIN32
    return VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    return mmap(addr, size, PAGE_EXECUTE_READWRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

void FreeMemory(void* addr, size_t size) {
#ifdef _WIN32
    VirtualFree(addr, size, MEM_RELEASE);
#else
    munmap(addr, size);
#endif
}

bool ProtectMemory(void* addr, size_t size) {
#ifdef _WIN32
    DWORD oldProt;
    return VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProt);
#else
    const size_t pageSize = sysconf(_SC_PAGE_SIZE);
    uintptr_t pageAddr = (uintptr_t) addr;
    pageAddr = pageAddr - (pageAddr % pageSize);
    return mprotect((void*) pageAddr, size, PAGE_EXECUTE_READWRITE) != -1;
#endif
}

void* AllocatePageNearAddress(void* targetAddr) {
#if _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const size_t pageSize = sysInfo.dwPageSize;
    uintptr_t minAddr = (uintptr_t) sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t) sysInfo.lpMaximumApplicationAddress;
#else
    const size_t pageSize = sysconf(_SC_PAGE_SIZE);
    uintptr_t minAddr = (uintptr_t) pageSize;
    uintptr_t maxAddr = (uintptr_t) (128ull * 1024 * 1024 * 1024 * 1024);
    using namespace std;
#endif

    uintptr_t startAddr = (uintptr_t(targetAddr) & ~(pageSize - 1)); //round down to nearest page boundary

    minAddr = min(startAddr - 0x7FFFFF00, minAddr);
    maxAddr = max(startAddr + 0x7FFFFF00, maxAddr);

    uintptr_t startPage = (startAddr - (startAddr % pageSize));
    uintptr_t pageOffset = 1;

    while (true) {
        uintptr_t byteOffset = pageOffset * pageSize;
        uintptr_t highAddr = startPage + byteOffset;
        uintptr_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

        bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

        if (highAddr < maxAddr) {
            void* outAddr = AllocateMemory((void*) highAddr, pageSize);
            if (outAddr != nullptr && outAddr != (void *)-1)
                return outAddr;
        }

        if (lowAddr > minAddr) {
            void* outAddr = AllocateMemory((void*) lowAddr, pageSize);
            if (outAddr != nullptr && outAddr != (void *)-1)
                return outAddr;
        }

        pageOffset++;

        if (needsExit)
            break;
    }

    return nullptr;
}

void FreePage(void* pageAdr) {
#if _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const size_t pageSize = sysInfo.dwPageSize;
#else
    const size_t pageSize = sysconf(_SC_PAGE_SIZE);
#endif
    FreeMemory(pageAdr, pageSize);
}

bool IsRelativeJump(const cs_insn& inst) {
    bool isAnyJumpInstruction = inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS;
    bool isJmp = inst.id == X86_INS_JMP;
    bool startsWithEBorE9 = inst.bytes[0] == 0xEB || inst.bytes[0] == 0xE9;
    return isJmp ? startsWithEBorE9 : isAnyJumpInstruction;
}

bool IsRelativeCall(const cs_insn& inst) {
    bool isCall = inst.id == X86_INS_CALL;
    bool startsWithE8 = inst.bytes[0] == 0xE8;
    return isCall && startsWithE8;
}

bool IsRIPRelativeInstr(const cs_insn& inst) {
    const cs_x86& x86 = inst.detail->x86;

    for (size_t i = 0; i < x86.op_count; ++i) {
        const cs_x86_op& op = x86.operands[i];

        //mem type is rip relative, like lea rcx,[rip+0xbeef]
        if (op.type == X86_OP_MEM) {
            //if we're relative to rip
            return op.mem.base == X86_REG_RIP;
        }
    }

    return false;
}

bool IsLoopInstr(const cs_insn& inst) {
    return inst.id >= X86_INS_LOOP && inst.id <= X86_INS_LOOPNE;
}

size_t WriteRelativeJump32(void* relJumpMemory, void* addrToJumpTo) {
    /**
     * 0:  e9 00 00 00 00          jmp    0x5
     */
    uint8_t jmpInstruction[] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

    uint32_t relAddr = (uintptr_t) relJumpMemory - ((uintptr_t) addrToJumpTo + sizeof(jmpInstruction));
    memcpy(&jmpInstruction[1], &relAddr, sizeof(relAddr));
    memcpy(addrToJumpTo, jmpInstruction, sizeof(jmpInstruction));

    return sizeof(jmpInstruction);
}

size_t WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo) {
#ifdef ENV64BIT
    /**
     * 0:  48 b8 00 00 00 00 00    movabs rax,0x0
     * 7:  00 00 00
     * a:  ff e0                   jmp    rax
     */
    uint8_t absJumpInstructions[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

    uintptr_t addrToJumpTo64 = (uintptr_t) addrToJumpTo;
    memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
    memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
#else // ENV32BIT
    /**
     * 0:  68 00 00 00 00          push   0x0
     * 5:  c3                      ret
     */
    uint8_t absJumpInstructions[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };

    uintptr_t addrToJumpTo32 = (uintptr_t) addrToJumpTo;
    memcpy(&absJumpInstructions[1], &addrToJumpTo32, sizeof(addrToJumpTo32));
    memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
#endif // ENV64BIT

    return sizeof(absJumpInstructions);
}

#ifdef ENV64BIT
#define CONVERT(S) strtoull(S, nullptr, 0)
#else
#define CONVERT(S) strtoul(S, nullptr, 0)
#endif

uint32_t AddJmpToAbsTable(cs_insn& jmp, uint8_t* absTableMem) {
    char* targetAddrStr = jmp.op_str; //where the instruction intended to go
    uintptr_t targetAddr = CONVERT(targetAddrStr);

    return WriteAbsoluteJump64(absTableMem, (void*) targetAddr);
}

uint32_t AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc) {
    char* targetAddrStr = call.op_str; //where the instruction intended to go
    uintptr_t targetAddr = CONVERT(targetAddrStr);

    uint8_t* dstMem = absTableMem;
#ifdef ENV64BIT
    /**
     * 0:  48 b8 00 00 00 00 00    movabs rax,0x0
     * 7:  00 00 00
     * a:  ff d0                   call   rax
     */
    uint8_t callAsmBytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0 };

    memcpy(&callAsmBytes[2], &targetAddr, sizeof(targetAddr));
#else // ENV32BIT
    /**
     * 0:  b8 00 00 00 00          mov    eax,0x0
     * 5:  ff d0                   call   eax
     */
    uint8_t callAsmBytes[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0 };

    memcpy(&callAsmBytes[1], &targetAddr, sizeof(targetAddr));
#endif // ENV64BIT

    memcpy(dstMem, &callAsmBytes, sizeof(callAsmBytes));
    dstMem += sizeof(callAsmBytes);

    //after the call, we need to add a second 2 byte jump, which will jump back to the
    //final jump of the stolen bytes
    uint8_t jmpBytes[2] = { 0xEB, uint8_t(jumpBackToHookedFunc - (absTableMem + sizeof(jmpBytes))) };
    memcpy(dstMem, jmpBytes, sizeof(jmpBytes));

    return sizeof(callAsmBytes) + sizeof(jmpBytes); //14
}

template<class T>
T GetDisplacement(const cs_insn& inst, uint8_t offset) {
    T disp;
    memcpy(&disp, &inst.bytes[offset], sizeof(T));
    return disp;
}

//rewrite instruction bytes so that any RIP-relative displacement operands
//make sense with wherever we're relocating to
void RelocateInstruction(cs_insn& inst, void* dstLocation) {
    const cs_x86& x86 = inst.detail->x86;
    uint8_t offset = x86.encoding.disp_offset;

    switch (x86.encoding.disp_size) {
        case 1: {
            int8_t disp = GetDisplacement<int8_t>(inst, offset);
            disp -= int8_t(uintptr_t(dstLocation) - inst.address);
            memcpy(&inst.bytes[offset], &disp, 1);
            break;
        }

        case 2: {
            int16_t disp = GetDisplacement<int16_t>(inst, offset);
            disp -= int16_t(uintptr_t(dstLocation) - inst.address);
            memcpy(&inst.bytes[offset], &disp, 2);
            break;
        }

        case 4: {
            int32_t disp = GetDisplacement<int32_t>(inst, offset);
            disp -= int32_t(uintptr_t(dstLocation) - inst.address);
            memcpy(&inst.bytes[offset], &disp, 4);
            break;
        }
    }
}

void RewriteJumpInstruction(cs_insn& instr, const uint8_t* instrPtr, const uint8_t* absTableEntry) {
    uint8_t distToJumpTable = uint8_t(absTableEntry - (instrPtr + instr.size));

    //jmp instructions can have a 1 or 2 byte opcode, and need a 1-4 byte operand
    //rewrite the operand for the jump to go to the jump table
    uint8_t instrByteSize = instr.bytes[0] == 0x0F ? 2 : 1;
    uint8_t operandSize = instr.size - instrByteSize;

    switch (operandSize) {
        case 1: { instr.bytes[instrByteSize] = distToJumpTable; break; }
        case 2: { uint16_t dist16 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist16, 2); break; }
        case 4: { uint32_t dist32 = distToJumpTable; memcpy(&instr.bytes[instrByteSize], &dist32, 4); break; }
    }
}

void RewriteCallInstruction(cs_insn& instr, const uint8_t* instrPtr, const uint8_t* absTableEntry) {
    uint8_t distToJumpTable = uint8_t(absTableEntry - (instrPtr + instr.size));

    //calls need to be rewritten as relative jumps to the abs table
    //but we want to preserve the length of the instruction, so pad with NOPs
    uint8_t jmpBytes[2] = { 0xEB, distToJumpTable };
    memset(instr.bytes, 0x90, instr.size);
    memcpy(instr.bytes, jmpBytes, sizeof(jmpBytes));
}

uint32_t BuildTrampoline(void* func2hook, void* dstMemForTrampoline, std::vector<uint8_t>& dstOriginalInstructions) {
#if ENV64BIT
    cs_mode mode = CS_MODE_64;
#else
    cs_mode mode = CS_MODE_32;
#endif

    // Allow to write and read
    ProtectMemory(func2hook, 20);

    // Disassemble stolen bytes
    csh handle;
    cs_open(CS_ARCH_X86, mode, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // we need details enabled for relocating RIP relative instrs

    cs_insn* instructions; //allocated by cs_disasm, needs to be manually freed later
    size_t count = cs_disasm(handle, (uint8_t*) func2hook, 20, (uintptr_t) func2hook, 20, &instructions);

    // Get the instructions covered by the first 5 bytes of the original function
    size_t byteCount = 0;
    size_t stolenInstrCount = 0;
    for (size_t i = 0; i < count; ++i) {
        cs_insn& inst = instructions[i];
        byteCount += inst.size;
        stolenInstrCount++;
        if (byteCount >= 5) break;
    }

    // Save original instructions
    dstOriginalInstructions.resize(byteCount);
    memcpy(dstOriginalInstructions.data(), func2hook, byteCount);

    // Replace instructions in target func with NOPs
    memset(func2hook, 0x90, byteCount);

#if ENV64BIT
    const size_t jumpInstSize = 12; //12 is the size of a 64 bit mov/jmp instruction pair
#else
    const size_t jumpInstSize = 6; //6 is the size of a 32 bit push/ret instruction pair
#endif

    uint8_t* stolenByteMem = (uint8_t*) dstMemForTrampoline;
    uint8_t* jumpBackMem = stolenByteMem + byteCount;
    uint8_t* absTableMem = jumpBackMem + jumpInstSize;

    for (size_t i = 0; i < stolenInstrCount; ++i) {
        cs_insn& inst = instructions[i];

        if (IsLoopInstr(inst))
            return 0; // TODO: bail out on loop instructions, I don't have a good way of handling them
        else if (IsRIPRelativeInstr(inst)) {
            RelocateInstruction(inst, stolenByteMem);
        } else if (IsRelativeJump(inst)) {
            uint32_t aitSize = AddJmpToAbsTable(inst, absTableMem);
            RewriteJumpInstruction(inst, stolenByteMem, absTableMem);
            absTableMem += aitSize;
        } else if (IsRelativeCall(inst)) {
            uint32_t aitSize = AddCallToAbsTable(inst, absTableMem, jumpBackMem);
            RewriteCallInstruction(inst, stolenByteMem, absTableMem);
            absTableMem += aitSize;
        }

        memcpy(stolenByteMem, inst.bytes, inst.size);
        stolenByteMem += inst.size;
    }

    WriteAbsoluteJump64(jumpBackMem, (uint8_t*) func2hook + 5);

    cs_close(&handle);
    cs_free(instructions, count);

    return uint32_t(absTableMem - (uint8_t*) dstMemForTrampoline);
}