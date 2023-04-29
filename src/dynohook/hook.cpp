#include "hook.h"

#include <asmjit/asmjit.h>

using namespace dyno;
using namespace asmjit;
using namespace asmjit::x86;

Hook::Hook(const ConvFunc& convention) :
    m_bridge(nullptr),
    m_newRetAddr(nullptr),
    m_callingConvention(convention()),
    m_registers(m_callingConvention->getRegisters()),
    m_scratchRegisters(Registers::ScratchList()) {
}

void Hook::addCallback(HookType hookType, HookHandler* handler) {
    if (!handler)
        return;

    std::vector<HookHandler*>& callbacks = m_handlers[hookType];

    for (const HookHandler* callback : callbacks) {
        if (callback == handler)
            return;
    }

    callbacks.push_back(handler);
}

void Hook::removeCallback(HookType hookType, HookHandler* handler) {
    if (!handler)
        return;

    auto it = m_handlers.find(hookType);
    if (it == m_handlers.end())
        return;

    std::vector<HookHandler*>& callbacks = it->second;

    for (size_t i = 0; i < callbacks.size(); ++i) {
        if (callbacks[i] == handler) {
            callbacks.erase(callbacks.begin() + i);
            if (callbacks.empty())
                m_handlers.erase(it);
            return;
        }
    }
}

bool Hook::isCallbackRegistered(HookType hookType, HookHandler* handler) const {
    auto it = m_handlers.find(hookType);
    if (it == m_handlers.end())
        return false;

    const std::vector<HookHandler*>& callbacks = it->second;

    for (const HookHandler* callback : callbacks) {
        if (callback == handler)
            return true;
    }

    return false;
}

bool Hook::areCallbacksRegistered() const {
    auto it = m_handlers.find(HookType::Pre);
    if (it != m_handlers.end() && !it->second.empty())
        return true;

    it = m_handlers.find(HookType::Post);
    if (it != m_handlers.end() && !it->second.empty())
        return true;

    return false;
}

ReturnAction Hook::hookHandler(HookType hookType) {
    if (hookType == HookType::Post) {
        ReturnAction lastPreReturnAction = m_lastPreReturnAction.back();
        m_lastPreReturnAction.pop_back();
        if (lastPreReturnAction >= ReturnAction::Override)
            m_callingConvention->restoreReturnValue(m_registers);
        if (lastPreReturnAction < ReturnAction::Supercede)
            m_callingConvention->restoreCallArguments(m_registers);
    }

    ReturnAction returnAction = ReturnAction::Ignored;
    auto it = m_handlers.find(hookType);
    if (it == m_handlers.end()) {
        // still save the arguments for the post hook even if there
        // is no pre-handler registered.
        if (hookType == HookType::Pre) {
            m_lastPreReturnAction.push_back(returnAction);
            m_callingConvention->saveCallArguments(m_registers);
        }
        return returnAction;
    }

    const std::vector<HookHandler*>& callbacks = it->second;

    for (const HookHandler* callback : callbacks) {
        ReturnAction result = ((HookHandler) callback)(hookType, *this);
        if (result > returnAction)
            returnAction = result;
    }

    if (hookType == HookType::Pre) {
        m_lastPreReturnAction.push_back(returnAction);
        if (returnAction >= ReturnAction::Override)
            m_callingConvention->saveReturnValue(m_registers);
        if (returnAction < ReturnAction::Supercede)
            m_callingConvention->saveCallArguments(m_registers);
    }

    return returnAction;
}

void* Hook::getReturnAddress(void* stackPtr) {
    auto it = m_retAddr.find(stackPtr);
    if (it == m_retAddr.end()) {
        puts("[Error] - Hook - Failed to find return address of original function. Check the arguments and return type of your detour setup.");
        return nullptr;
    }

    std::vector<void*>& v = it->second;
    void* retAddr = v.back();
    v.pop_back();

    // clear the stack address from the cache now that we ran the last post hook.
    if (v.empty())
        m_retAddr.erase(it);

    return retAddr;
}

void Hook::setReturnAddress(void* retAddr, void* stackPtr) {
    m_retAddr[stackPtr].push_back(retAddr);
}

bool Hook::createBridge() const {
    // holds code and relocation information during code generation
    CodeHolder code;

    // code holder must be initialized before it can be used
    code.init(Environment::host(), CpuInfo::host().features());

    // emitters can emit code to CodeHolder
    Assembler a(&code);
    Label override = a.newLabel();

    // write a redirect to the post-hook code
    writeModifyReturnAddress(a);

    // call the pre-hook handler and jump to label override if true was returned
    writeCallHandler(a, HookType::Pre);
    a.cmp(al, ReturnAction::Supercede);

    // restore the previously saved registers, so any changes will be applied
    writeRestoreRegisters(a, HookType::Pre);

    // skip trampoline if equal
    a.je(override);

    // jump to the trampoline/original
    a.jmp(getOriginal());

    // this code will be executed if a pre-hook returns true
    a.bind(override);

    // finally, return to the caller
    // this will still call post hooks, but will skip the original function.
    size_t popSize = m_callingConvention->getPopSize();
    if (popSize > 0)
        a.ret(popSize);
    else
        a.ret();

    // generate code
    code.flatten();
    code.resolveUnresolvedLinks();

    // now relocate the code to the address provided by the memory allocator
    code.relocateToBase((uint64_t) m_bridge);

    // this will copy code from all sections to our memory
    Error err = code.copyFlattenedData(m_bridge, code.codeSize(), CopySectionFlags::kPadSectionBuffer);
    if (err) {
        puts(DebugUtils::errorAsString(err));
        return false;
    }

    return true;
}

void Hook::writeModifyReturnAddress(Assembler& a) const {
    /// https://en.wikipedia.org/wiki/X86_calling_conventions

    // save scratch registers that are used by setReturnAddress
    writeSaveScratchRegisters(a);

    // save the original return address by using the current esp as the key.
    // this should be unique until we have returned to the original caller.
    void (DYNO_CDECL Hook::*setReturnAddress)(void*, void*) = &Hook::setReturnAddress;

#if DYNO_ARCH_X86 == 64
#ifdef DYNO_PLATFORM_WINDOWS
    a.mov(r8, rsp);
    a.mov(rdx, qword_ptr(rsp));
    a.mov(rcx, this);
    a.sub(rsp, 40);
    a.call((void*&) setReturnAddress); // +8 = 48 (aligned by 16 bytes)
    a.add(rsp, 40);
#else // __systemV__
    a.mov(rdx, rsp);
    a.mov(rsi, qword_ptr(rsp));
    a.mov(rdi, this);
    a.sub(rsp, 24);
    a.call((void*&) setReturnAddress); // +8 = 32 (aligned by 16 bytes)
    a.add(rsp, 24);
#endif
#elif DYNO_ARCH_X86 == 32
    // store the return address in eax
    a.mov(eax, dword_ptr(esp));

    a.push(esp);
    a.push(eax);
    a.push(this);
    a.call((void*&) setReturnAddress); // +4 = 16 (aligned by 16 bytes)
    a.add(esp, 12);
#endif // DYNO_ARCH_X86

    // restore scratch registers
    writeRestoreScratchRegisters(a);

    // override the return address. This is a redirect to our post-hook code
    createPostCallback();
#if DYNO_ARCH_X86 == 64
    // using rax because not possible to MOV r/m64, imm64
    a.mov(qword_ptr(rsp), rax);
    a.mov(rax, m_newRetAddr);
    a.xchg(qword_ptr(rsp), rax);
#elif DYNO_ARCH_X86 == 32
    a.mov(dword_ptr(esp), m_newRetAddr);
#endif // DYNO_ARCH_X86
}

bool Hook::createPostCallback() const {
    // holds code and relocation information during code generation
    CodeHolder code;

    // code holder must be initialized before it can be used
    code.init(Environment::host(), CpuInfo::host().features());

    // emitters can emit code to CodeHolder
    Assembler a(&code);

    // gets pop size + return address
    size_t popSize = m_callingConvention->getPopSize() + sizeof(void*);

    // subtract the previously added bytes (stack size + return address), so
    // that we can access the arguments again
#if DYNO_ARCH_X86 == 64
    a.sub(rsp, popSize);
#elif DYNO_ARCH_X86 == 32
    a.sub(esp, popSize);
#endif // DYNO_ARCH_X86

    // call the post-hook handler
    writeCallHandler(a, HookType::Post);

    // restore the previously saved registers, so any changes will be applied
    writeRestoreRegisters(a, HookType::Post);

    // save scratch registers that are used by getReturnAddress
    writeSaveScratchRegisters(a);

    // get the original return address
    void* (DYNO_CDECL Hook::*getReturnAddress)(void*) = &Hook::getReturnAddress;

#if DYNO_ARCH_X86 == 64
#ifdef DYNO_PLATFORM_WINDOWS
    a.mov(rdx, rsp);
    a.mov(rcx, this);
    a.sub(rsp, 40);
    a.call((void*&) getReturnAddress); // +8 = 48 (aligned by 16 bytes)
    a.add(rsp, 40);
#else // __systemV__
    a.mov(rsi, rsp);
    a.mov(rdi, this);
    a.sub(rsp, 24);
    a.call((void*&) getReturnAddress); // +8 = 32 (aligned by 16 bytes)
    a.add(rsp, 24);
#endif
    // save the original return address
    a.push(rax);
#elif DYNO_ARCH_X86 == 32
    // store stack pointer in eax
    a.mov(eax, esp);

    // subtract 4 bytes to preserve 16-byte stack alignment for Linux
    a.sub(esp, 4);
    a.push(eax);
    a.push(this);
    a.call((void*&) getReturnAddress); // +4 = 16 (aligned by 16 bytes)
    a.add(esp, 12);

    // save the original return address
    a.push(eax);
#endif // DYNO_ARCH_X86

    // restore scratch registers
    writeRestoreScratchRegisters(a);

    // return to the original address
    // add the bytes again to the stack (stack size + return address), so we
    // don't corrupt the stack.
    a.ret(popSize);

    // generate code
    code.flatten();
    code.resolveUnresolvedLinks();

    // now relocate the code to the address provided by the memory allocator
    code.relocateToBase((uint64_t) m_newRetAddr);

    // this will copy code from all sections to our memory
    Error err = code.copyFlattenedData(m_newRetAddr, code.codeSize(), CopySectionFlags::kPadSectionBuffer);
    if (err) {
        puts(DebugUtils::errorAsString(err));
        return false;
    }

    return true;
}

void Hook::writeCallHandler(Assembler& a, HookType hookType) const {
    ReturnAction (DYNO_CDECL Hook::*hookHandler)(HookType) = &Hook::hookHandler;

    // save the registers so that we can access them in our handlers
    writeSaveRegisters(a, hookType);

    // call the global hook handler
#if DYNO_ARCH_X86 == 64
#ifdef DYNO_PLATFORM_WINDOWS
    a.mov(rdx, hookType);
    a.mov(rcx, this);
    a.sub(rsp, 40);
    a.call((void*&) hookHandler); // +8 = 48 (aligned by 16 bytes)
    a.add(rsp, 40);
#else // __systemV__
    a.mov(rsi, hookType);
    a.mov(rdi, this);
    a.sub(rsp, 24);
    a.call((void*&) hookHandler); // +8 = 32 (aligned by 16 bytes)
    a.add(rsp, 24);
#endif
#elif DYNO_ARCH_X86 == 32
    // subtract 4 bytes to preserve 16-byte stack alignment for Linux
    a.sub(esp, 4);
    a.push(hookType);
    a.push(this);
    a.call((void*&) hookHandler); // +4 = 16 (aligned by 16 bytes)
    a.add(esp, 12);
#endif // DYNO_ARCH_X86
}

#if DYNO_ARCH_X86 == 64

void Hook::writeSaveScratchRegisters(Assembler& a) const {
    // save rax first, because we use it to save others

    for (const auto& reg : m_scratchRegisters) {
        if (reg == RAX) {
            writeRegToMem(a, reg);
            break;
        }
    }

    for (const auto& reg : m_scratchRegisters) {
        if (reg != RAX)
            writeRegToMem(a, reg);
    }
}

void Hook::writeRestoreScratchRegisters(Assembler& a) const {
    // restore rax last, because we use it to restore others

    for (const auto& reg : m_scratchRegisters) {
        if (reg != RAX)
            writeMemToReg(a, reg);
    }

    for (const auto& reg : m_scratchRegisters) {
        if (reg == RAX) {
            writeMemToReg(a, reg);
            break;
        }
    }
}

void Hook::writeSaveRegisters(Assembler& a, HookType hookType) const {
    // save rax first, because we use it to save others

    for (const auto& reg : m_registers) {
        if (reg == RAX) {
            writeRegToMem(a, reg);
            break;
        }
    }

    for (const auto& reg : m_registers) {
        if (reg != RAX)
            writeRegToMem(a, reg);
    }
}

void Hook::writeRestoreRegisters(Assembler& a, HookType hookType) const {
    // restore rax last, because we use it to restore others

    for (const auto& reg : m_registers) {
        if (reg != RAX)
            writeMemToReg(a, reg);
    }

    for (const auto& reg : m_registers) {
        if (reg == RAX) {
            writeMemToReg(a, reg);
            break;
        }
    }
}

void Hook::writeRegToMem(Assembler& a, const Register& reg, HookType hookType) const {
    /**
     * The moffs8, moffs16, moffs32 and moffs64 operands specify a simple offset relative to the segment base,
     * where 8, 16, 32 and 64 refer to the size of the data. The address-size attribute of the instruction determines the size of the offset, either 16, 32 or 64 bits.
     * Supported only by RAX, EAX, AX, AL registers.
     */
    uint64_t addr = reg.getAddress<uint64_t>();
    switch (reg) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: a.mov(byte_ptr(addr), al); break;
        case CL: a.mov(rax, addr); a.mov(byte_ptr(rax), cl); break;
        case DL: a.mov(rax, addr); a.mov(byte_ptr(rax), dl); break;
        case BL: a.mov(rax, addr); a.mov(byte_ptr(rax), bl); break;

        case SPL: a.mov(rax, addr); a.mov(byte_ptr(rax), spl); break;
        case BPL: a.mov(rax, addr); a.mov(byte_ptr(rax), bpl); break;
        case SIL: a.mov(rax, addr); a.mov(byte_ptr(rax), sil); break;
        case DIL: a.mov(rax, addr); a.mov(byte_ptr(rax), dil); break;
        case R8B: a.mov(rax, addr); a.mov(byte_ptr(rax), r8b); break;
        case R9B: a.mov(rax, addr); a.mov(byte_ptr(rax), r9b); break;
        case R10B: a.mov(rax, addr); a.mov(byte_ptr(rax), r10b); break;
        case R11B: a.mov(rax, addr); a.mov(byte_ptr(rax), r11b); break;
        case R12B: a.mov(rax, addr); a.mov(byte_ptr(rax), r12b); break;
        case R13B: a.mov(rax, addr); a.mov(byte_ptr(rax), r13b); break;
        case R14B: a.mov(rax, addr); a.mov(byte_ptr(rax), r14b); break;
        case R15B: a.mov(rax, addr); a.mov(byte_ptr(rax), r15b); break;

        case AH: a.mov(rax, addr); a.mov(byte_ptr(rax), ah); break;
        case CH: a.mov(rax, addr); a.mov(byte_ptr(rax), ch); break;
        case DH: a.mov(rax, addr); a.mov(byte_ptr(rax), dh); break;
        case BH: a.mov(rax, addr); a.mov(byte_ptr(rax), bh); break;

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        case AX: a.mov(word_ptr(addr), ax); break;
        case CX: a.mov(rax, addr); a.mov(word_ptr(rax), cx); break;
        case DX: a.mov(rax, addr); a.mov(word_ptr(rax), dx); break;
        case BX: a.mov(rax, addr); a.mov(word_ptr(rax), bx); break;
        case SP: a.mov(rax, addr); a.mov(word_ptr(rax), sp); break;
        case BP: a.mov(rax, addr); a.mov(word_ptr(rax), bp); break;
        case SI: a.mov(rax, addr); a.mov(word_ptr(rax), si); break;
        case DI: a.mov(rax, addr); a.mov(word_ptr(rax), di); break;

        case R8W: a.mov(rax, addr); a.mov(word_ptr(rax), r8w); break;
        case R9W: a.mov(rax, addr); a.mov(word_ptr(rax), r9w); break;
        case R10W: a.mov(rax, addr); a.mov(word_ptr(rax), r10w); break;
        case R11W: a.mov(rax, addr); a.mov(word_ptr(rax), r11w); break;
        case R12W: a.mov(rax, addr); a.mov(word_ptr(rax), r12w); break;
        case R13W: a.mov(rax, addr); a.mov(word_ptr(rax), r13w); break;
        case R14W: a.mov(rax, addr); a.mov(word_ptr(rax), r14w); break;
        case R15W: a.mov(rax, addr); a.mov(word_ptr(rax), r15w); break;

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        case EAX: a.mov(dword_ptr(addr), eax); break;
        case ECX: a.mov(rax, addr); a.mov(dword_ptr(rax), ecx); break;
        case EDX: a.mov(rax, addr); a.mov(dword_ptr(rax), edx); break;
        case EBX: a.mov(rax, addr); a.mov(dword_ptr(rax), ebx); break;
        case ESP: a.mov(rax, addr); a.mov(dword_ptr(rax), esp); break;
        case EBP: a.mov(rax, addr); a.mov(dword_ptr(rax), ebp); break;
        case ESI: a.mov(rax, addr); a.mov(dword_ptr(rax), esi); break;
        case EDI: a.mov(rax, addr); a.mov(dword_ptr(rax), edi); break;

        case R8D: a.mov(rax, addr); a.mov(dword_ptr(rax), r8d); break;
        case R9D: a.mov(rax, addr); a.mov(dword_ptr(rax), r9d); break;
        case R10D: a.mov(rax, addr); a.mov(dword_ptr(rax), r10d); break;
        case R11D: a.mov(rax, addr); a.mov(dword_ptr(rax), r11d); break;
        case R12D: a.mov(rax, addr); a.mov(dword_ptr(rax), r12d); break;
        case R13D: a.mov(rax, addr); a.mov(dword_ptr(rax), r13d); break;
        case R14D: a.mov(rax, addr); a.mov(dword_ptr(rax), r14d); break;
        case R15D: a.mov(rax, addr); a.mov(dword_ptr(rax), r15d); break;

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
        case RAX: a.mov(qword_ptr(addr), rax); break;
        case RCX: a.mov(rax, addr); a.mov(qword_ptr(rax), rcx); break;
        case RDX: a.mov(rax, addr); a.mov(qword_ptr(rax), rdx); break;
        case RBX: a.mov(rax, addr); a.mov(qword_ptr(rax), rbx); break;
        case RSP: a.mov(rax, addr); a.mov(qword_ptr(rax), rsp); break;
        case RBP: a.mov(rax, addr); a.mov(qword_ptr(rax), rbp); break;
        case RSI: a.mov(rax, addr); a.mov(qword_ptr(rax), rsi); break;
        case RDI: a.mov(rax, addr); a.mov(qword_ptr(rax), rdi); break;

        case R8: a.mov(rax, addr); a.mov(qword_ptr(rax), r8); break;
        case R9: a.mov(rax, addr); a.mov(qword_ptr(rax), r9); break;
        case R10: a.mov(rax, addr); a.mov(qword_ptr(rax), r10); break;
        case R11: a.mov(rax, addr); a.mov(qword_ptr(rax), r11); break;
        case R12: a.mov(rax, addr); a.mov(qword_ptr(rax), r12); break;
        case R13: a.mov(rax, addr); a.mov(qword_ptr(rax), r13); break;
        case R14: a.mov(rax, addr); a.mov(qword_ptr(rax), r14); break;
        case R15: a.mov(rax, addr); a.mov(qword_ptr(rax), r15); break;

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        case MM0: a.mov(rax, addr); a.movq(qword_ptr(rax), mm0); break;
        case MM1: a.mov(rax, addr); a.movq(qword_ptr(rax), mm1); break;
        case MM2: a.mov(rax, addr); a.movq(qword_ptr(rax), mm2); break;
        case MM3: a.mov(rax, addr); a.movq(qword_ptr(rax), mm3); break;
        case MM4: a.mov(rax, addr); a.movq(qword_ptr(rax), mm4); break;
        case MM5: a.mov(rax, addr); a.movq(qword_ptr(rax), mm5); break;
        case MM6: a.mov(rax, addr); a.movq(qword_ptr(rax), mm6); break;
        case MM7: a.mov(rax, addr); a.movq(qword_ptr(rax), mm7); break;

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm0); break;
        case XMM1: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm1); break;
        case XMM2: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm2); break;
        case XMM3: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm3); break;
        case XMM4: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm4); break;
        case XMM5: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm5); break;
        case XMM6: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm6); break;
        case XMM7: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm7); break;
        case XMM8: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm8); break;
        case XMM9: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm9); break;
        case XMM10: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm10); break;
        case XMM11: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm11); break;
        case XMM12: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm12); break;
        case XMM13: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm13); break;
        case XMM14: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm14); break;
        case XMM15: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm15); break;
#ifdef DYNO_PLATFORM_AVX512
        case XMM16: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm16); break;
        case XMM17: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm17); break;
        case XMM18: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm18); break;
        case XMM19: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm19); break;
        case XMM20: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm20); break;
        case XMM21: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm21); break;
        case XMM22: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm22); break;
        case XMM23: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm23); break;
        case XMM24: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm24); break;
        case XMM25: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm25); break;
        case XMM26: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm26); break;
        case XMM27: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm27); break;
        case XMM28: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm28); break;
        case XMM29: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm29); break;
        case XMM30: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm30); break;
        case XMM31: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm31); break;
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
        case YMM0: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm0); break;
        case YMM1: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm1); break;
        case YMM2: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm2); break;
        case YMM3: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm3); break;
        case YMM4: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm4); break;
        case YMM5: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm5); break;
        case YMM6: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm6); break;
        case YMM7: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm7); break;
        case YMM8: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm8); break;
        case YMM9: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm9); break;
        case YMM10: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm10); break;
        case YMM11: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm11); break;
        case YMM12: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm12); break;
        case YMM13: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm13); break;
        case YMM14: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm14); break;
        case YMM15: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm15); break;
#ifdef DYNO_PLATFORM_AVX512
        case YMM16: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm16); break;
        case YMM17: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm17); break;
        case YMM18: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm18); break;
        case YMM19: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm19); break;
        case YMM20: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm20); break;
        case YMM21: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm21); break;
        case YMM22: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm22); break;
        case YMM23: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm23); break;
        case YMM24: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm24); break;
        case YMM25: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm25); break;
        case YMM26: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm26); break;
        case YMM27: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm27); break;
        case YMM28: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm28); break;
        case YMM29: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm29); break;
        case YMM30: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm30); break;
        case YMM31: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm31); break;
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case ZMM0: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm0); break;
        case ZMM1: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm1); break;
        case ZMM2: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm2); break;
        case ZMM3: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm3); break;
        case ZMM4: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm4); break;
        case ZMM5: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm5); break;
        case ZMM6: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm6); break;
        case ZMM7: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm7); break;
        case ZMM8: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm8); break;
        case ZMM9: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm9); break;
        case ZMM10: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm10); break;
        case ZMM11: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm11); break;
        case ZMM12: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm12); break;
        case ZMM13: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm13); break;
        case ZMM14: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm14); break;
        case ZMM15: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm15); break;
        case ZMM16: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm16); break;
        case ZMM17: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm17); break;
        case ZMM18: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm18); break;
        case ZMM19: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm19); break;
        case ZMM20: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm20); break;
        case ZMM21: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm21); break;
        case ZMM22: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm22); break;
        case ZMM23: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm23); break;
        case ZMM24: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm24); break;
        case ZMM25: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm25); break;
        case ZMM26: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm26); break;
        case ZMM27: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm27); break;
        case ZMM28: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm28); break;
        case ZMM29: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm29); break;
        case ZMM30: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm30); break;
        case ZMM31: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm31); break;
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        case CS: a.mov(rax, addr); a.mov(word_ptr(rax), cs); break;
        case SS: a.mov(rax, addr); a.mov(word_ptr(rax), ss); break;
        case DS: a.mov(rax, addr); a.mov(word_ptr(rax), ds); break;
        case ES: a.mov(rax, addr); a.mov(word_ptr(rax), es); break;
        case FS: a.mov(rax, addr); a.mov(word_ptr(rax), fs); break;
        case GS: a.mov(rax, addr); a.mov(word_ptr(rax), gs); break;

        default: puts("[Warning] - Hook - Unsupported register.");
    }
}

void Hook::writeMemToReg(Assembler& a, const Register& reg, HookType hookType) const {
    /**
     * The moffs8, moffs16, moffs32 and moffs64 operands specify a simple offset relative to the segment base,
     * where 8, 16, 32 and 64 refer to the size of the data. The address-size attribute of the instruction determines the size of the offset, either 16, 32 or 64 bits.
     * Supported only by RAX, EAX, AX, AL registers.
     */
    uint64_t addr = reg.getAddress<uint64_t>();
    switch (reg) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: a.mov(al, byte_ptr(addr)); break;
        case CL: a.mov(rax, addr); a.mov(cl, byte_ptr(rax)); break;
        case DL: a.mov(rax, addr); a.mov(dl, byte_ptr(rax)); break;
        case BL: a.mov(rax, addr); a.mov(bl, byte_ptr(rax)); break;

        case SPL: a.mov(rax, addr); a.mov(spl, byte_ptr(rax)); break;
        case BPL: a.mov(rax, addr); a.mov(bpl, byte_ptr(rax)); break;
        case SIL: a.mov(rax, addr); a.mov(sil, byte_ptr(rax)); break;
        case DIL: a.mov(rax, addr); a.mov(dil, byte_ptr(rax)); break;
        case R8B: a.mov(rax, addr); a.mov(r8b, byte_ptr(rax)); break;
        case R9B: a.mov(rax, addr); a.mov(r9b, byte_ptr(rax)); break;
        case R10B: a.mov(rax, addr); a.mov(r10b, byte_ptr(rax)); break;
        case R11B: a.mov(rax, addr); a.mov(r11b, byte_ptr(rax)); break;
        case R12B: a.mov(rax, addr); a.mov(r12b, byte_ptr(rax)); break;
        case R13B: a.mov(rax, addr); a.mov(r13b, byte_ptr(rax)); break;
        case R14B: a.mov(rax, addr); a.mov(r14b, byte_ptr(rax)); break;
        case R15B: a.mov(rax, addr); a.mov(r15b, byte_ptr(rax)); break;

        case AH: a.mov(rax, addr); a.mov(ah, byte_ptr(rax)); break;
        case CH: a.mov(rax, addr); a.mov(ch, byte_ptr(rax)); break;
        case DH: a.mov(rax, addr); a.mov(dh, byte_ptr(rax)); break;
        case BH: a.mov(rax, addr); a.mov(bh, byte_ptr(rax)); break;

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        case AX: a.mov(ax, word_ptr(addr)); break;
        case CX: a.mov(rax, addr); a.mov(cx, word_ptr(rax)); break;
        case DX: a.mov(rax, addr); a.mov(dx, word_ptr(rax)); break;
        case BX: a.mov(rax, addr); a.mov(bx, word_ptr(rax)); break;
        case SP: a.mov(rax, addr); a.mov(sp, word_ptr(rax)); break;
        case BP: a.mov(rax, addr); a.mov(bp, word_ptr(rax)); break;
        case SI: a.mov(rax, addr); a.mov(si, word_ptr(rax)); break;
        case DI: a.mov(rax, addr); a.mov(di, word_ptr(rax)); break;

        case R8W: a.mov(rax, addr); a.mov(r8w, word_ptr(rax)); break;
        case R9W: a.mov(rax, addr); a.mov(r9w, word_ptr(rax)); break;
        case R10W: a.mov(rax, addr); a.mov(r10w, word_ptr(rax)); break;
        case R11W: a.mov(rax, addr); a.mov(r11w, word_ptr(rax)); break;
        case R12W: a.mov(rax, addr); a.mov(r12w, word_ptr(rax)); break;
        case R13W: a.mov(rax, addr); a.mov(r13w, word_ptr(rax)); break;
        case R14W: a.mov(rax, addr); a.mov(r14w, word_ptr(rax)); break;
        case R15W: a.mov(rax, addr); a.mov(r15w, word_ptr(rax)); break;

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        case EAX: a.mov(eax, dword_ptr(addr)); break;
        case ECX: a.mov(rax, addr); a.mov(ecx, dword_ptr(rax)); break;
        case EDX: a.mov(rax, addr); a.mov(edx, dword_ptr(rax)); break;
        case EBX: a.mov(rax, addr); a.mov(ebx, dword_ptr(rax)); break;
        case ESP: a.mov(rax, addr); a.mov(esp, dword_ptr(rax)); break;
        case EBP: a.mov(rax, addr); a.mov(ebp, dword_ptr(rax)); break;
        case ESI: a.mov(rax, addr); a.mov(esi, dword_ptr(rax)); break;
        case EDI: a.mov(rax, addr); a.mov(edi, dword_ptr(rax)); break;

        case R8D: a.mov(rax, addr); a.mov(r8d, dword_ptr(rax)); break;
        case R9D: a.mov(rax, addr); a.mov(r9d, dword_ptr(rax)); break;
        case R10D: a.mov(rax, addr); a.mov(r10d, dword_ptr(rax)); break;
        case R11D: a.mov(rax, addr); a.mov(r11d, dword_ptr(rax)); break;
        case R12D: a.mov(rax, addr); a.mov(r12d, dword_ptr(rax)); break;
        case R13D: a.mov(rax, addr); a.mov(r13d, dword_ptr(rax)); break;
        case R14D: a.mov(rax, addr); a.mov(r14d, dword_ptr(rax)); break;
        case R15D: a.mov(rax, addr); a.mov(r15d, dword_ptr(rax)); break;

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
        case RAX: a.mov(rax, qword_ptr(addr)); break;
        case RCX: a.mov(rax, addr); a.mov(rcx, qword_ptr(rax)); break;
        case RDX: a.mov(rax, addr); a.mov(rdx, qword_ptr(rax)); break;
        case RBX: a.mov(rax, addr); a.mov(rbx, qword_ptr(rax)); break;
        case RSP: a.mov(rax, addr); a.mov(rsp, qword_ptr(rax)); break;
        case RBP: a.mov(rax, addr); a.mov(rbp, qword_ptr(rax)); break;
        case RSI: a.mov(rax, addr); a.mov(rsi, qword_ptr(rax)); break;
        case RDI: a.mov(rax, addr); a.mov(rdi, qword_ptr(rax)); break;

        case R8: a.mov(rax, addr); a.mov(r8, qword_ptr(rax)); break;
        case R9: a.mov(rax, addr); a.mov(r9, qword_ptr(rax)); break;
        case R10: a.mov(rax, addr); a.mov(r10, qword_ptr(rax)); break;
        case R11: a.mov(rax, addr); a.mov(r11, qword_ptr(rax)); break;
        case R12: a.mov(rax, addr); a.mov(r12, qword_ptr(rax)); break;
        case R13: a.mov(rax, addr); a.mov(r13, qword_ptr(rax)); break;
        case R14: a.mov(rax, addr); a.mov(r14, qword_ptr(rax)); break;
        case R15: a.mov(rax, addr); a.mov(r15, qword_ptr(rax)); break;

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        case MM0: a.mov(rax, addr); a.movq(mm0, qword_ptr(rax)); break;
        case MM1: a.mov(rax, addr); a.movq(mm1, qword_ptr(rax)); break;
        case MM2: a.mov(rax, addr); a.movq(mm2, qword_ptr(rax)); break;
        case MM3: a.mov(rax, addr); a.movq(mm3, qword_ptr(rax)); break;
        case MM4: a.mov(rax, addr); a.movq(mm4, qword_ptr(rax)); break;
        case MM5: a.mov(rax, addr); a.movq(mm5, qword_ptr(rax)); break;
        case MM6: a.mov(rax, addr); a.movq(mm6, qword_ptr(rax)); break;
        case MM7: a.mov(rax, addr); a.movq(mm7, qword_ptr(rax)); break;

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: a.mov(rax, addr); a.movaps(xmm0, xmmword_ptr(rax)); break;
        case XMM1: a.mov(rax, addr); a.movaps(xmm1, xmmword_ptr(rax)); break;
        case XMM2: a.mov(rax, addr); a.movaps(xmm2, xmmword_ptr(rax)); break;
        case XMM3: a.mov(rax, addr); a.movaps(xmm3, xmmword_ptr(rax)); break;
        case XMM4: a.mov(rax, addr); a.movaps(xmm4, xmmword_ptr(rax)); break;
        case XMM5: a.mov(rax, addr); a.movaps(xmm5, xmmword_ptr(rax)); break;
        case XMM6: a.mov(rax, addr); a.movaps(xmm6, xmmword_ptr(rax)); break;
        case XMM7: a.mov(rax, addr); a.movaps(xmm7, xmmword_ptr(rax)); break;
        case XMM8: a.mov(rax, addr); a.movaps(xmm8, xmmword_ptr(rax)); break;
        case XMM9: a.mov(rax, addr); a.movaps(xmm9, xmmword_ptr(rax)); break;
        case XMM10: a.mov(rax, addr); a.movaps(xmm10, xmmword_ptr(rax)); break;
        case XMM11: a.mov(rax, addr); a.movaps(xmm11, xmmword_ptr(rax)); break;
        case XMM12: a.mov(rax, addr); a.movaps(xmm12, xmmword_ptr(rax)); break;
        case XMM13: a.mov(rax, addr); a.movaps(xmm13, xmmword_ptr(rax)); break;
        case XMM14: a.mov(rax, addr); a.movaps(xmm14, xmmword_ptr(rax)); break;
        case XMM15: a.mov(rax, addr); a.movaps(xmm15, xmmword_ptr(rax)); break;
#ifdef DYNO_PLATFORM_AVX512
        case XMM16: a.mov(rax, addr); a.movaps(xmm16, xmmword_ptr(rax)); break;
        case XMM17: a.mov(rax, addr); a.movaps(xmm17, xmmword_ptr(rax)); break;
        case XMM18: a.mov(rax, addr); a.movaps(xmm18, xmmword_ptr(rax)); break;
        case XMM19: a.mov(rax, addr); a.movaps(xmm19, xmmword_ptr(rax)); break;
        case XMM20: a.mov(rax, addr); a.movaps(xmm20, xmmword_ptr(rax)); break;
        case XMM21: a.mov(rax, addr); a.movaps(xmm21, xmmword_ptr(rax)); break;
        case XMM22: a.mov(rax, addr); a.movaps(xmm22, xmmword_ptr(rax)); break;
        case XMM23: a.mov(rax, addr); a.movaps(xmm23, xmmword_ptr(rax)); break;
        case XMM24: a.mov(rax, addr); a.movaps(xmm24, xmmword_ptr(rax)); break;
        case XMM25: a.mov(rax, addr); a.movaps(xmm25, xmmword_ptr(rax)); break;
        case XMM26: a.mov(rax, addr); a.movaps(xmm26, xmmword_ptr(rax)); break;
        case XMM27: a.mov(rax, addr); a.movaps(xmm27, xmmword_ptr(rax)); break;
        case XMM28: a.mov(rax, addr); a.movaps(xmm28, xmmword_ptr(rax)); break;
        case XMM29: a.mov(rax, addr); a.movaps(xmm29, xmmword_ptr(rax)); break;
        case XMM30: a.mov(rax, addr); a.movaps(xmm30, xmmword_ptr(rax)); break;
        case XMM31: a.mov(rax, addr); a.movaps(xmm31, xmmword_ptr(rax)); break;
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
        case YMM0: a.mov(rax, addr); a.vmovaps(ymm0, ymmword_ptr(rax)); break;
        case YMM1: a.mov(rax, addr); a.vmovaps(ymm1, ymmword_ptr(rax)); break;
        case YMM2: a.mov(rax, addr); a.vmovaps(ymm2, ymmword_ptr(rax)); break;
        case YMM3: a.mov(rax, addr); a.vmovaps(ymm3, ymmword_ptr(rax)); break;
        case YMM4: a.mov(rax, addr); a.vmovaps(ymm4, ymmword_ptr(rax)); break;
        case YMM5: a.mov(rax, addr); a.vmovaps(ymm5, ymmword_ptr(rax)); break;
        case YMM6: a.mov(rax, addr); a.vmovaps(ymm6, ymmword_ptr(rax)); break;
        case YMM7: a.mov(rax, addr); a.vmovaps(ymm7, ymmword_ptr(rax)); break;
        case YMM8: a.mov(rax, addr); a.vmovaps(ymm8, ymmword_ptr(rax)); break;
        case YMM9: a.mov(rax, addr); a.vmovaps(ymm9, ymmword_ptr(rax)); break;
        case YMM10: a.mov(rax, addr); a.vmovaps(ymm10, ymmword_ptr(rax)); break;
        case YMM11: a.mov(rax, addr); a.vmovaps(ymm11, ymmword_ptr(rax)); break;
        case YMM12: a.mov(rax, addr); a.vmovaps(ymm12, ymmword_ptr(rax)); break;
        case YMM13: a.mov(rax, addr); a.vmovaps(ymm13, ymmword_ptr(rax)); break;
        case YMM14: a.mov(rax, addr); a.vmovaps(ymm14, ymmword_ptr(rax)); break;
        case YMM15: a.mov(rax, addr); a.vmovaps(ymm15, ymmword_ptr(rax)); break;
#ifdef DYNO_PLATFORM_AVX512
        case YMM16: a.mov(rax, addr); a.vmovaps(ymm16, ymmword_ptr(rax)); break;
        case YMM17: a.mov(rax, addr); a.vmovaps(ymm17, ymmword_ptr(rax)); break;
        case YMM18: a.mov(rax, addr); a.vmovaps(ymm18, ymmword_ptr(rax)); break;
        case YMM19: a.mov(rax, addr); a.vmovaps(ymm19, ymmword_ptr(rax)); break;
        case YMM20: a.mov(rax, addr); a.vmovaps(ymm20, ymmword_ptr(rax)); break;
        case YMM21: a.mov(rax, addr); a.vmovaps(ymm21, ymmword_ptr(rax)); break;
        case YMM22: a.mov(rax, addr); a.vmovaps(ymm22, ymmword_ptr(rax)); break;
        case YMM23: a.mov(rax, addr); a.vmovaps(ymm23, ymmword_ptr(rax)); break;
        case YMM24: a.mov(rax, addr); a.vmovaps(ymm24, ymmword_ptr(rax)); break;
        case YMM25: a.mov(rax, addr); a.vmovaps(ymm25, ymmword_ptr(rax)); break;
        case YMM26: a.mov(rax, addr); a.vmovaps(ymm26, ymmword_ptr(rax)); break;
        case YMM27: a.mov(rax, addr); a.vmovaps(ymm27, ymmword_ptr(rax)); break;
        case YMM28: a.mov(rax, addr); a.vmovaps(ymm28, ymmword_ptr(rax)); break;
        case YMM29: a.mov(rax, addr); a.vmovaps(ymm29, ymmword_ptr(rax)); break;
        case YMM30: a.mov(rax, addr); a.vmovaps(ymm30, ymmword_ptr(rax)); break;
        case YMM31: a.mov(rax, addr); a.vmovaps(ymm31, ymmword_ptr(rax)); break;
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case ZMM0: a.mov(rax, addr); a.vmovaps(zmm0, zmmword_ptr(rax)); break;
        case ZMM1: a.mov(rax, addr); a.vmovaps(zmm1, zmmword_ptr(rax)); break;
        case ZMM2: a.mov(rax, addr); a.vmovaps(zmm2, zmmword_ptr(rax)); break;
        case ZMM3: a.mov(rax, addr); a.vmovaps(zmm3, zmmword_ptr(rax)); break;
        case ZMM4: a.mov(rax, addr); a.vmovaps(zmm4, zmmword_ptr(rax)); break;
        case ZMM5: a.mov(rax, addr); a.vmovaps(zmm5, zmmword_ptr(rax)); break;
        case ZMM6: a.mov(rax, addr); a.vmovaps(zmm6, zmmword_ptr(rax)); break;
        case ZMM7: a.mov(rax, addr); a.vmovaps(zmm7, zmmword_ptr(rax)); break;
        case ZMM8: a.mov(rax, addr); a.vmovaps(zmm8, zmmword_ptr(rax)); break;
        case ZMM9: a.mov(rax, addr); a.vmovaps(zmm9, zmmword_ptr(rax)); break;
        case ZMM10: a.mov(rax, addr); a.vmovaps(zmm10, zmmword_ptr(rax)); break;
        case ZMM11: a.mov(rax, addr); a.vmovaps(zmm11, zmmword_ptr(rax)); break;
        case ZMM12: a.mov(rax, addr); a.vmovaps(zmm12, zmmword_ptr(rax)); break;
        case ZMM13: a.mov(rax, addr); a.vmovaps(zmm13, zmmword_ptr(rax)); break;
        case ZMM14: a.mov(rax, addr); a.vmovaps(zmm14, zmmword_ptr(rax)); break;
        case ZMM15: a.mov(rax, addr); a.vmovaps(zmm15, zmmword_ptr(rax)); break;
        case ZMM16: a.mov(rax, addr); a.vmovaps(zmm16, zmmword_ptr(rax)); break;
        case ZMM17: a.mov(rax, addr); a.vmovaps(zmm17, zmmword_ptr(rax)); break;
        case ZMM18: a.mov(rax, addr); a.vmovaps(zmm18, zmmword_ptr(rax)); break;
        case ZMM19: a.mov(rax, addr); a.vmovaps(zmm19, zmmword_ptr(rax)); break;
        case ZMM20: a.mov(rax, addr); a.vmovaps(zmm20, zmmword_ptr(rax)); break;
        case ZMM21: a.mov(rax, addr); a.vmovaps(zmm21, zmmword_ptr(rax)); break;
        case ZMM22: a.mov(rax, addr); a.vmovaps(zmm22, zmmword_ptr(rax)); break;
        case ZMM23: a.mov(rax, addr); a.vmovaps(zmm23, zmmword_ptr(rax)); break;
        case ZMM24: a.mov(rax, addr); a.vmovaps(zmm24, zmmword_ptr(rax)); break;
        case ZMM25: a.mov(rax, addr); a.vmovaps(zmm25, zmmword_ptr(rax)); break;
        case ZMM26: a.mov(rax, addr); a.vmovaps(zmm26, zmmword_ptr(rax)); break;
        case ZMM27: a.mov(rax, addr); a.vmovaps(zmm27, zmmword_ptr(rax)); break;
        case ZMM28: a.mov(rax, addr); a.vmovaps(zmm28, zmmword_ptr(rax)); break;
        case ZMM29: a.mov(rax, addr); a.vmovaps(zmm29, zmmword_ptr(rax)); break;
        case ZMM30: a.mov(rax, addr); a.vmovaps(zmm30, zmmword_ptr(rax)); break;
        case ZMM31: a.mov(rax, addr); a.vmovaps(zmm31, zmmword_ptr(rax)); break;
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        case CS: a.mov(rax, addr); a.mov(cs, word_ptr(rax)); break;
        case SS: a.mov(rax, addr); a.mov(ss, word_ptr(rax)); break;
        case DS: a.mov(rax, addr); a.mov(ds, word_ptr(rax)); break;
        case ES: a.mov(rax, addr); a.mov(es, word_ptr(rax)); break;
        case FS: a.mov(rax, addr); a.mov(fs, word_ptr(rax)); break;
        case GS: a.mov(rax, addr); a.mov(gs, word_ptr(rax)); break;

        default: puts("[Warning] - Hook - Unsupported register.");
    }
}

#elif DYNO_ARCH_X86 == 32

void Hook::writeSaveScratchRegisters(Assembler& a) const {
    for (const auto& reg : m_scratchRegisters) {
        writeRegToMem(a, reg);
    }
}

void Hook::writeRestoreScratchRegisters(Assembler& a) const {
    for (const auto& reg : m_scratchRegisters) {
        writeMemToReg(a, reg);
    }
}

void Hook::writeSaveRegisters(Assembler& a, HookType hookType) const {
    for (const auto& reg : m_registers) {
        writeRegToMem(a, reg, hookType);
    }
}

void Hook::writeRestoreRegisters(Assembler& a, HookType hookType) const {
    for (const auto& reg : m_registers) {
        writeMemToReg(a, reg, hookType);
    }
}

void Hook::writeRegToMem(Assembler& a, const Register& reg, HookType hookType) const {
    uint64_t addr = reg.getAddress<uint64_t>();
    switch (reg) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: a.mov(byte_ptr(addr), al); break;
        case CL: a.mov(byte_ptr(addr), cl); break;
        case DL: a.mov(byte_ptr(addr), dl); break;
        case BL: a.mov(byte_ptr(addr), bl); break;

        case AH: a.mov(byte_ptr(addr), ah); break;
        case CH: a.mov(byte_ptr(addr), ch); break;
        case DH: a.mov(byte_ptr(addr), dh); break;
        case BH: a.mov(byte_ptr(addr), bh); break;

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        case AX: a.mov(word_ptr(addr), ax); break;
        case CX: a.mov(word_ptr(addr), cx); break;
        case DX: a.mov(word_ptr(addr), dx); break;
        case BX: a.mov(word_ptr(addr), bx); break;
        case SP: a.mov(word_ptr(addr), sp); break;
        case BP: a.mov(word_ptr(addr), bp); break;
        case SI: a.mov(word_ptr(addr), si); break;
        case DI: a.mov(word_ptr(addr), di); break;

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        case EAX: a.mov(dword_ptr(addr), eax); break;
        case ECX: a.mov(dword_ptr(addr), ecx); break;
        case EDX: a.mov(dword_ptr(addr), edx); break;
        case EBX: a.mov(dword_ptr(addr), ebx); break;
        case ESP: a.mov(dword_ptr(addr), esp); break;
        case EBP: a.mov(dword_ptr(addr), ebp); break;
        case ESI: a.mov(dword_ptr(addr), esi); break;
        case EDI: a.mov(dword_ptr(addr), edi); break;

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        case MM0: a.movq(qword_ptr(addr), mm0); break;
        case MM1: a.movq(qword_ptr(addr), mm1); break;
        case MM2: a.movq(qword_ptr(addr), mm2); break;
        case MM3: a.movq(qword_ptr(addr), mm3); break;
        case MM4: a.movq(qword_ptr(addr), mm4); break;
        case MM5: a.movq(qword_ptr(addr), mm5); break;
        case MM6: a.movq(qword_ptr(addr), mm6); break;
        case MM7: a.movq(qword_ptr(addr), mm7); break;

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: a.movaps(dqword_ptr(addr), xmm0); break;
        case XMM1: a.movaps(dqword_ptr(addr), xmm1); break;
        case XMM2: a.movaps(dqword_ptr(addr), xmm2); break;
        case XMM3: a.movaps(dqword_ptr(addr), xmm3); break;
        case XMM4: a.movaps(dqword_ptr(addr), xmm4); break;
        case XMM5: a.movaps(dqword_ptr(addr), xmm5); break;
        case XMM6: a.movaps(dqword_ptr(addr), xmm6); break;
        case XMM7: a.movaps(dqword_ptr(addr), xmm7); break;

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        case CS: a.mov(word_ptr(addr), cs); break;
        case SS: a.mov(word_ptr(addr), ss); break;
        case DS: a.mov(word_ptr(addr), ds); break;
        case ES: a.mov(word_ptr(addr), es); break;
        case FS: a.mov(word_ptr(addr), fs); break;
        case GS: a.mov(word_ptr(addr), gs); break;

        // ========================================================================
        // >> 80-bit FPU registers
        // ========================================================================
        case ST0:
            // don't mess with the FPU stack in a pre-hook. The float return is returned in st0,
            // so only load it in a post hook to avoid writing back NaN.
            if (hookType == HookType::Post) {
                switch (m_callingConvention->getReturn().size) {
                    case SIZE_DWORD: a.fstp(dword_ptr(addr)); break;
                    case SIZE_QWORD: a.fstp(qword_ptr(addr)); break;
                    case SIZE_TWORD: a.fstp(tword_ptr(addr)); break;
                }
            }
            break;
        //case ST1: a.movl(tword_ptr(addr), st1); break;
        //case ST2: a.movl(tword_ptr(addr), st2); break;
        //case ST3: a.movl(tword_ptr(addr), st3); break;
        //case ST4: a.movl(tword_ptr(addr), st4); break;
        //case ST5: a.movl(tword_ptr(addr), st5); break;
        //case ST6: a.movl(tword_ptr(addr), st6); break;
        //case ST7: a.movl(tword_ptr(addr), st7); break;

        default: puts("[Warning] - Hook - Unsupported register.");
    }
}

void Hook::writeMemToReg(Assembler& a, const Register& reg, HookType hookType) const {
    uint64_t addr = reg.getAddress<uint64_t>();
    switch (reg) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: a.mov(al, byte_ptr(addr)); break;
        case CL: a.mov(cl, byte_ptr(addr)); break;
        case DL: a.mov(dl, byte_ptr(addr)); break;
        case BL: a.mov(bl, byte_ptr(addr)); break;

        case AH: a.mov(ah, byte_ptr(addr)); break;
        case CH: a.mov(ch, byte_ptr(addr)); break;
        case DH: a.mov(dh, byte_ptr(addr)); break;
        case BH: a.mov(bh, byte_ptr(addr)); break;

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        case AX: a.mov(ax, word_ptr(addr)); break;
        case CX: a.mov(cx, word_ptr(addr)); break;
        case DX: a.mov(dx, word_ptr(addr)); break;
        case BX: a.mov(bx, word_ptr(addr)); break;
        case SP: a.mov(sp, word_ptr(addr)); break;
        case BP: a.mov(bp, word_ptr(addr)); break;
        case SI: a.mov(si, word_ptr(addr)); break;
        case DI: a.mov(di, word_ptr(addr)); break;

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        case EAX: a.mov(eax, dword_ptr(addr)); break;
        case ECX: a.mov(ecx, dword_ptr(addr)); break;
        case EDX: a.mov(edx, dword_ptr(addr)); break;
        case EBX: a.mov(ebx, dword_ptr(addr)); break;
        case ESP: a.mov(esp, dword_ptr(addr)); break;
        case EBP: a.mov(ebp, dword_ptr(addr)); break;
        case ESI: a.mov(esi, dword_ptr(addr)); break;
        case EDI: a.mov(edi, dword_ptr(addr)); break;

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        case MM0: a.movq(mm0, qword_ptr(addr)); break;
        case MM1: a.movq(mm1, qword_ptr(addr)); break;
        case MM2: a.movq(mm2, qword_ptr(addr)); break;
        case MM3: a.movq(mm3, qword_ptr(addr)); break;
        case MM4: a.movq(mm4, qword_ptr(addr)); break;
        case MM5: a.movq(mm5, qword_ptr(addr)); break;
        case MM6: a.movq(mm6, qword_ptr(addr)); break;
        case MM7: a.movq(mm7, qword_ptr(addr)); break;

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: a.movaps(xmm0, dqword_ptr(addr)); break;
        case XMM1: a.movaps(xmm1, dqword_ptr(addr)); break;
        case XMM2: a.movaps(xmm2, dqword_ptr(addr)); break;
        case XMM3: a.movaps(xmm3, dqword_ptr(addr)); break;
        case XMM4: a.movaps(xmm4, dqword_ptr(addr)); break;
        case XMM5: a.movaps(xmm5, dqword_ptr(addr)); break;
        case XMM6: a.movaps(xmm6, dqword_ptr(addr)); break;
        case XMM7: a.movaps(xmm7, dqword_ptr(addr)); break;

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        case CS: a.mov(cs, word_ptr(addr)); break;
        case SS: a.mov(ss, word_ptr(addr)); break;
        case DS: a.mov(ds, word_ptr(addr)); break;
        case ES: a.mov(es, word_ptr(addr)); break;
        case FS: a.mov(fs, word_ptr(addr)); break;
        case GS: a.mov(gs, word_ptr(addr)); break;

        // ========================================================================
        // >> 80-bit FPU registers
        // ========================================================================
        case ST0:
            if (hookType == HookType::Post) {
                // replace the top of the FPU stack.
                // copy st0 to st0 and pop -> just pop the FPU stack.
                a.fstp(st0);
                // push a value to the FPU stack.
                // TODO: Only write back when changed? Save full 80bits for that case.
                //       Avoid truncation of the data if it's unchanged.
                switch (m_callingConvention->getReturn().size) {
                    case SIZE_DWORD: a.fld(dword_ptr(addr)); break;
                    case SIZE_QWORD: a.fld(qword_ptr(addr)); break;
                    case SIZE_TWORD: a.fld(tword_ptr(addr)); break;
                }
            }
            break;
        //case ST1: a.movl(st1, tword_ptr(addr)); break;
        //case ST2: a.movl(st2, tword_ptr(addr)); break;
        //case ST3: a.movl(st3, tword_ptr(addr)); break;
        //case ST4: a.movl(st4, tword_ptr(addr)); break;
        //case ST5: a.movl(st5, tword_ptr(addr)); break;
        //case ST6: a.movl(st6, tword_ptr(addr)); break;
        //case ST7: a.movl(st7, tword_ptr(addr)); break;

        default: puts("[Warning] - Hook - Unsupported register.");
    }
}

#endif // DYNO_ARCH_X86