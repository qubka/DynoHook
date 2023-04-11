#pragma once

struct cs_insn;

namespace dyno {
    bool IsRelativeJump(const cs_insn& inst);
    bool IsRelativeCall(const cs_insn& inst);
    bool IsRIPRelativeInstr(const cs_insn& inst);
    bool IsLoopInstr(const cs_insn& inst);

    size_t WriteRelativeJump(void* targetAddr, void* addrToJumpTo);
    size_t WriteAbsoluteJump(void* targetAddr, void* addrToJumpTo);

    uint32_t AddJmpToAbsTable(cs_insn& jmp, uint8_t* absTableMem);
    uint32_t AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc);

    void RelocateInstruction(cs_insn& inst, void* dstLocation);
    void RewriteJumpInstruction(cs_insn& inst, const uint8_t* instPtr, const uint8_t* absTableEntry);
    void RewriteCallInstruction(cs_insn& inst, const uint8_t* instPtr, const uint8_t* absTableEntry);
}