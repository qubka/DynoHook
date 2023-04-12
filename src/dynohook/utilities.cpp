#include "utilities.hpp"
#include "memory.hpp"

#include <capstone/capstone.h>

// From: http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html

namespace dyno {

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

    size_t WriteRelativeJump(void* targetAddr, void* addrToJumpTo) {
        /**
         * 0:  e9 00 00 00 00          jmp    0x5
         */
        uint8_t jmpInstruction[] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

        uint32_t relAddr = (uintptr_t) addrToJumpTo - ((uintptr_t) targetAddr + sizeof(jmpInstruction));
        std::memcpy(&jmpInstruction[1], &relAddr, sizeof(relAddr));
        std::memcpy(targetAddr, jmpInstruction, sizeof(jmpInstruction));

        return sizeof(jmpInstruction);
    }

    size_t WriteAbsoluteJump(void* targetAddr, void* addrToJumpTo) {
    #ifdef DYNO_PLATFORM_X64
        /**
         * 0:  48 b8 00 00 00 00 00    movabs rax,0x0
         * 7:  00 00 00
         * a:  ff e0                   jmp    rax
         */
        //uint8_t absJumpInstructions[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

        /**
         * 0:  50                      push   rax
         * 1:  48 b8 00 00 00 00 00    movabs rax,0x0
         * 8:  00 00 00
         * b:  48 87 04 24             xchg   QWORD PTR [rsp],rax
         * f:  c3                      ret
         */
        uint8_t absJumpInstructions[] = { 0x50, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x87, 0x04, 0x24, 0xC3 };

        uintptr_t addrToJumpTo64 = (uintptr_t) addrToJumpTo;
        std::memcpy(&absJumpInstructions[3], &addrToJumpTo64, sizeof(addrToJumpTo64));
        std::memcpy(targetAddr, absJumpInstructions, sizeof(absJumpInstructions));
    #else
        /**
         * 0:  68 00 00 00 00          push   0x0
         * 5:  c3                      ret
         */
        uint8_t absJumpInstructions[] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3 };

        uintptr_t addrToJumpTo32 = (uintptr_t) addrToJumpTo;
        std::memcpy(&absJumpInstructions[1], &addrToJumpTo32, sizeof(addrToJumpTo32));
        std::memcpy(targetAddr, absJumpInstructions, sizeof(absJumpInstructions));
    #endif // DYNO_PLATFORM_X64

        return sizeof(absJumpInstructions);
    }

    #ifdef DYNO_PLATFORM_X64
    #define CONVERT(S) strtoull(S, nullptr, 0)
    #else
    #define CONVERT(S) strtoul(S, nullptr, 0)
    #endif

    uint32_t AddJmpToAbsTable(cs_insn& jmp, uint8_t* absTableMem) {
        char* targetAddrStr = jmp.op_str; //where the instruction intended to go
        uintptr_t targetAddr = CONVERT(targetAddrStr);

        return WriteAbsoluteJump(absTableMem, (void*) targetAddr);
    }

    uint32_t AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc) {
        char* targetAddrStr = call.op_str; //where the instruction intended to go
        uintptr_t targetAddr = CONVERT(targetAddrStr);

        uint8_t* dstMem = absTableMem;
    #ifdef DYNO_PLATFORM_X64
        /**
         * 0:  48 b8 00 00 00 00 00    movabs rax,0x0
         * 7:  00 00 00
         * a:  ff d0                   call   rax
         */
        uint8_t callAsmBytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0 };

        std::memcpy(&callAsmBytes[2], &targetAddr, sizeof(targetAddr));
    #else
        /**
         * 0:  b8 00 00 00 00          mov    eax,0x0
         * 5:  ff d0                   call   eax
         */
        uint8_t callAsmBytes[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0 };

        std::memcpy(&callAsmBytes[1], &targetAddr, sizeof(targetAddr));
    #endif // DYNO_PLATFORM_X64

        std::memcpy(dstMem, &callAsmBytes, sizeof(callAsmBytes));
        dstMem += sizeof(callAsmBytes);

        //after the call, we need to add a second 2 byte jump, which will jump back to the
        //final jump of the stolen bytes
        uint8_t jmpBytes[2] = { 0xEB, uint8_t(jumpBackToHookedFunc - (absTableMem + sizeof(jmpBytes))) };
        std::memcpy(dstMem, jmpBytes, sizeof(jmpBytes));

        return sizeof(callAsmBytes) + sizeof(jmpBytes);
    }

    template<class T>
    void CalculateDisplacement(void* from, void* to, uintptr_t address) {
        T disp;
        std::memcpy(&disp, from, sizeof(T));
        disp -= T(uintptr_t(to) - address);
        std::memcpy(from, &disp, sizeof(T));
    }

    //rewrite instruction bytes so that any RIP-relative displacement operands
    //make sense with wherever we're relocating to
    void RelocateInstruction(cs_insn& inst, void* dstLocation) {
        const cs_x86& x86 = inst.detail->x86;
        uint8_t offset = x86.encoding.disp_offset;

        switch (x86.encoding.disp_size) {
            case 1: CalculateDisplacement<int8_t> (&inst.bytes[offset], dstLocation, inst.address); break;
            case 2: CalculateDisplacement<int16_t>(&inst.bytes[offset], dstLocation, inst.address); break;
            case 4: CalculateDisplacement<int32_t>(&inst.bytes[offset], dstLocation, inst.address); break;
        }
    }

    void RewriteJumpInstruction(cs_insn& inst, const uint8_t* instPtr, const uint8_t* absTableEntry) {
        uint8_t distToJumpTable = uint8_t(absTableEntry - (instPtr + inst.size));

        //jmp instructions can have a 1 or 2 byte opcode, and need a 1-4 byte operand
        //rewrite the operand for the jump to go to the jump table
        uint8_t instByteSize = inst.bytes[0] == 0x0F ? 2 : 1;
        uint8_t operandSize = inst.size - instByteSize;

        switch (operandSize) {
            case 1: { inst.bytes[instByteSize] = distToJumpTable; break; }
            case 2: { uint16_t dist16 = distToJumpTable; std::memcpy(&inst.bytes[instByteSize], &dist16, 2); break; }
            case 4: { uint32_t dist32 = distToJumpTable; std::memcpy(&inst.bytes[instByteSize], &dist32, 4); break; }
        }
    }

    void RewriteCallInstruction(cs_insn& inst, const uint8_t* instPtr, const uint8_t* absTableEntry) {
        uint8_t distToJumpTable = uint8_t(absTableEntry - (instPtr + inst.size));

        //calls need to be rewritten as relative jumps to the abs table
        //but we want to preserve the length of the instruction, so pad with NOPs
        uint8_t jmpBytes[2] = { 0xEB, distToJumpTable };
        memset(inst.bytes, 0x90, inst.size);
        std::memcpy(inst.bytes, jmpBytes, sizeof(jmpBytes));
    }

}

