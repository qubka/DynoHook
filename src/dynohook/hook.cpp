#include "hook.hpp"
#include "utilities.hpp"

using namespace dyno;
using namespace asmjit;
using namespace asmjit::x86;

Hook::Hook(asmjit::JitRuntime& jit, void* func2hook, ICallingConvention* convention) :
        m_Jit{jit},
        m_pFunc{func2hook},
        m_pCallingConvention{convention},
        m_Registers{convention->getRegisters()},
        m_ScratchRegisters{createScratchRegisters()}
{
    // Allocate memory for the trampoline
    m_pTrampoline = AllocatePageNearAddress(func2hook);
    uint32_t trampolineSize = BuildTrampoline(func2hook, m_pTrampoline, m_OriginalInstructions);

    // Create the bridge function
    createBridge();

    // Write a jump to the bridge
    void* bridgeFuncMemory = (int8_t*) m_pTrampoline + trampolineSize;
    WriteAbsoluteJump64(bridgeFuncMemory, m_pBridge); //write bridge func instructions

    // Write a relative jump to the bridge
    WriteRelativeJump32(bridgeFuncMemory, func2hook);
}

Hook::~Hook() {
    delete m_pCallingConvention;

    // Free the trampoline array
    FreePage(m_pTrampoline);

    // Free the asm bridge and new return address
    m_Jit.release(m_pBridge);
    m_Jit.release(m_pNewRetAddr);

    // Probably hook wasn't generated successfully
    if (!m_OriginalInstructions.empty())
        // Copy back the previously copied bytes
        memcpy(m_pFunc, m_OriginalInstructions.data(), m_OriginalInstructions.size());
}

void Hook::addCallback(HookType hookType, HookHandler* pCallback) {
    if (!pCallback)
        return;

    std::vector<HookHandler*>& callbacks = m_Handlers[hookType];

    for (const HookHandler* callback : callbacks) {
        if (callback == pCallback)
            return;
    }

    callbacks.push_back(pCallback);
}

void Hook::removeCallback(HookType hookType, HookHandler* pCallback) {
    if (!pCallback)
        return;

    auto it = m_Handlers.find(hookType);
    if (it == m_Handlers.end())
        return;

    std::vector<HookHandler*>& callbacks = it->second;

    for (size_t i = 0; i < callbacks.size(); ++i) {
        if (callbacks[i] == pCallback) {
            callbacks.erase(callbacks.begin() + i);
            return;
        }
    }
}

bool Hook::isCallbackRegistered(HookType hookType, HookHandler* pCallback) const {
    auto it = m_Handlers.find(hookType);
    if (it == m_Handlers.end())
        return false;

    const std::vector<HookHandler*>& callbacks = it->second;

    for (const HookHandler* callback : callbacks) {
        if (callback == pCallback)
            return true;
    }

    return false;
}

bool Hook::areCallbacksRegistered() const {
    auto it = m_Handlers.find(HookType::Pre);
    if (it != m_Handlers.end() && !it->second.empty())
        return true;

    it = m_Handlers.find(HookType::Post);
    if (it != m_Handlers.end() && !it->second.empty())
        return true;

    return false;
}

ReturnAction Hook::hookHandler(HookType hookType) {
    if (hookType == HookType::Post) {
        ReturnAction lastPreReturnAction = m_LastPreReturnAction.back();
        m_LastPreReturnAction.pop_back();
        if (lastPreReturnAction >= ReturnAction::Override)
            m_pCallingConvention->restoreReturnValue(m_Registers);
        if (lastPreReturnAction < ReturnAction::Supercede)
            m_pCallingConvention->restoreCallArguments(m_Registers);
    }

    ReturnAction returnAction = ReturnAction::Ignored;
    auto it = m_Handlers.find(hookType);
    if (it == m_Handlers.end()) {
        // Still save the arguments for the post hook even if there
        // is no pre-handler registered.
        if (hookType == HookType::Pre) {
            m_LastPreReturnAction.push_back(returnAction);
            m_pCallingConvention->saveCallArguments(m_Registers);
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
        m_LastPreReturnAction.push_back(returnAction);
        if (returnAction >= ReturnAction::Override)
            m_pCallingConvention->saveReturnValue(m_Registers);
        if (returnAction < ReturnAction::Supercede)
            m_pCallingConvention->saveCallArguments(m_Registers);
    }

    return returnAction;
}

void* Hook::getReturnAddress(void* stackPtr) {
    auto it = m_RetAddr.find(stackPtr);
    if (it == m_RetAddr.end()) {
        puts("Failed to find return address of original function. Check the arguments and return type of your detour setup.");
        return nullptr;
    }

    std::vector<void*>& v = it->second;
    void* pRetAddr = v.back();
    v.pop_back();

    // Clear the stack address from the cache now that we ran the last post hook.
    if (v.empty())
        m_RetAddr.erase(it);

    return pRetAddr;
}

void Hook::setReturnAddress(void* retAddr, void* stackPtr) {
    m_RetAddr[stackPtr].push_back(retAddr);
}

// Used to print generated assembly
#if 0
FileLogger logger(stdout);
#define LOGGER(a) a.setLogger(&logger);
#else
#define LOGGER(a)
#endif

void Hook::createBridge() const {
    // Holds code and relocation information during code generation.
    CodeHolder code;

    // Code holder must be initialized before it can be used.
    code.init(m_Jit.environment(), m_Jit.cpuFeatures());

    // Emitters can emit code to CodeHolder
    Assembler a{&code}; LOGGER(a);
    Label override = a.newLabel();

    // Write a redirect to the post-hook code
    writeModifyReturnAddress(a);

    // Call the pre-hook handler and jump to label override if true was returned
    writeCallHandler(a, HookType::Pre);
    a.cmp(al, ReturnAction::Supercede);

    // Restore the previously saved registers, so any changes will be applied
    writeRestoreRegisters(a, HookType::Pre);

    // Skip trampoline if equal
    a.je(override);

    // Jump to the trampoline
    a.jmp(m_pTrampoline);

    // This code will be executed if a pre-hook returns true
    a.bind(override);

    // Finally, return to the caller
    // This will still call post hooks, but will skip the original function.
    size_t popSize = m_pCallingConvention->getPopSize();
    if (popSize > 0)
        a.ret(imm(popSize));
    else
        a.ret();

    // Generate code
    m_Jit.add(&m_pBridge, &code);
}

void Hook::writeModifyReturnAddress(Assembler& a) const {
    /// https://en.wikipedia.org/wiki/X86_calling_conventions

    // Save scratch registers that are used by setReturnAddress
    writeSaveScratchRegisters(a);

    // Save the original return address by using the current esp as the key.
    // This should be unique until we have returned to the original caller.
    void (ASMJIT_CDECL Hook::*setReturnAddress)(void*, void*) = &Hook::setReturnAddress;

#ifdef ENV64BIT
    // Store the return address and stack pointer in rax/rcx
    a.mov(rax, qword_ptr(rsp));
    a.mov(rcx, rsp);

#if _WIN64
    a.sub(rsp, 40);
    a.mov(r8, rcx);
    a.mov(rdx, rax);
    a.mov(rcx, imm(uintptr_t(this)));
    a.call((void*&) setReturnAddress);
    a.add(rsp, 40);
#else // __linux__
    a.mov(rdx, rcx);
    a.mov(rsi, rax);
    a.mov(rdi, imm(uintptr_t(this)));
    a.call((void*&) setReturnAddress);
#endif
#else // ENV32BIT
    // Store the return address in eax
    a.mov(eax, dword_ptr(esp));

    a.push(esp);
    a.push(eax);
    a.push(imm(uintptr_t(this)));
    a.call((void*&) setReturnAddress);
    a.add(esp, 12);
#endif // ENV32BIT

    // Restore scratch registers
    writeRestoreScratchRegisters(a);

    // Override the return address. This is a redirect to our post-hook code
    createPostCallback();
#ifdef ENV64BIT
    // Using rax because not possible to MOV r/m64, imm64
    a.push(rax);
    a.mov(rax, imm(uintptr_t(m_pNewRetAddr)));
    a.mov(qword_ptr(rsp, 8), rax);
    a.pop(rax);
#else // ENV32BIT
    a.mov(dword_ptr(esp), uintptr_t(m_pNewRetAddr));
#endif
}

void Hook::createPostCallback() const {
    // Holds code and relocation information during code generation.
    CodeHolder code;

    // Code holder must be initialized before it can be used.
    code.init(m_Jit.environment(), m_Jit.cpuFeatures());

    // Emitters can emit code to CodeHolder
    Assembler a{&code}; LOGGER(a);

    // Gets pop size + return address
    size_t popSize = m_pCallingConvention->getPopSize() + sizeof(void*);

    // Subtract the previously added bytes (stack size + return address), so
    // that we can access the arguments again
#ifdef ENV64BIT
    a.sub(rsp, imm(popSize));
#else // ENV32BIT
    a.sub(esp, imm(popSize));
#endif

    // Call the post-hook handler
    writeCallHandler(a, HookType::Post);

    // Restore the previously saved registers, so any changes will be applied
    writeRestoreRegisters(a, HookType::Post);

    // Save scratch registers that are used by GetReturnAddress
    writeSaveScratchRegisters(a);

    // Get the original return address
    void* (ASMJIT_CDECL Hook::*getReturnAddress)(void*) = &Hook::getReturnAddress;

#ifdef ENV64BIT
    // Save current stack pointer
    a.mov(rax, rsp);

#if _WIN64
    a.sub(rsp, 40);
    a.mov(rdx, rax);
    a.mov(rcx, imm(uintptr_t(this)));
    a.call((void*&) getReturnAddress);
    a.add(rsp, 40);
#else // __linux__
    a.mov(rsi, rax);
    a.mov(rdi, imm(uintptr_t(this)));
    a.call((void*&) getReturnAddress);
#endif
    // Save the original return address
    a.mov(qword_ptr(uintptr_t(&m_pRetAddr)), rax);
#else // ENV32BIT
    a.push(esp);
    a.push(imm(uintptr_t(this)));
    a.call((void*&) getReturnAddress);
    a.add(esp, 8);

    // Save the original return address
    a.mov(dword_ptr(uintptr_t(&m_pRetAddr)), eax);
#endif

    // Restore scratch registers
    writeRestoreScratchRegisters(a);

#ifdef ENV64BIT
    // Add the bytes again to the stack (return address), so we
    // don't corrupt the stack.
    a.add(rsp, imm(popSize));

    // Jump to the original return address
    a.jmp(qword_ptr(uintptr_t(&m_pRetAddr)));
#else // ENV32BIT
    // Add the bytes again to the stack (stack size + return address), so we
    // don't corrupt the stack.
    a.add(esp, imm(popSize));

    // Jump to the original return address
    a.jmp(dword_ptr(uintptr_t(&m_pRetAddr)));
#endif

    // Generate code
    m_Jit.add(&m_pNewRetAddr, &code);
}

void Hook::writeCallHandler(Assembler& a, HookType hookType) const {
    ReturnAction (ASMJIT_CDECL Hook::*hookHandler)(HookType) = &Hook::hookHandler;

    // Save the registers so that we can access them in our handlers
    writeSaveRegisters(a, hookType);

    // Call the global hook handler
#ifdef ENV64BIT
#if _WIN64
    a.sub(rsp, 40);
    a.mov(dl, hookType);
    a.mov(rcx, imm(uintptr_t(this)));
    a.call((void *&) hookHandler);
    a.add(rsp, 40);
#else // __linux__
    a.mov(sil, hookType);
    a.mov(rdi, imm(uintptr_t(this)));
    a.call((void*&) hookHandler);
#endif
#else // ENV32BIT
	// Subtract 4 bytes to preserve 16-Byte stack alignment for Linux
	a.sub(esp, 4);
	a.push(hookType);
	a.push(imm(uintptr_t(this)));
	a.call((void *&) hookHandler);
	a.add(esp, 12);
#endif
}

std::vector<RegisterType> Hook::createScratchRegisters() const {
    // https://www.agner.org/optimize/calling_conventions.pdf

    std::vector<RegisterType> registers;
    
#ifdef ENV64BIT
#if _WIN64
    registers.push_back(RAX);
    registers.push_back(RCX);
    registers.push_back(RDX);
    registers.push_back(R8);
    registers.push_back(R9);
    registers.push_back(R10);
    registers.push_back(R11);
#else // __linux__
    registers.push_back(RAX);
    registers.push_back(RDI);
    registers.push_back(RSI);
    registers.push_back(RDX);
    registers.push_back(RCX);
    registers.push_back(R8);
    registers.push_back(R9);
    registers.push_back(R10);
    registers.push_back(R11);
#endif
// TODO: Do we need to save all sse registers ?
#ifdef AVX512
    registers.push_back(ZMM0);
    registers.push_back(ZMM1);
    registers.push_back(ZMM2);
    registers.push_back(ZMM3);
    registers.push_back(ZMM4);
    registers.push_back(ZMM5);
    registers.push_back(ZMM6);
    registers.push_back(ZMM7);
    registers.push_back(ZMM8);
    registers.push_back(ZMM9);
    registers.push_back(ZMM10);
    registers.push_back(ZMM11);
    registers.push_back(ZMM12);
    registers.push_back(ZMM13);
    registers.push_back(ZMM14);
    registers.push_back(ZMM15);
    registers.push_back(ZMM16);
    registers.push_back(ZMM17);
    registers.push_back(ZMM18);
    registers.push_back(ZMM19);
    registers.push_back(ZMM20);
    registers.push_back(ZMM21);
    registers.push_back(ZMM22);
    registers.push_back(ZMM23);
    registers.push_back(ZMM24);
    registers.push_back(ZMM25);
    registers.push_back(ZMM26);
    registers.push_back(ZMM27);
    registers.push_back(ZMM28);
    registers.push_back(ZMM29);
    registers.push_back(ZMM30);
    registers.push_back(ZMM31);
#else
    registers.push_back(YMM0);
    registers.push_back(YMM1);
    registers.push_back(YMM2);
    registers.push_back(YMM3);
    registers.push_back(YMM4);
    registers.push_back(YMM5);
    registers.push_back(YMM6);
    registers.push_back(YMM7);
    registers.push_back(YMM8);
    registers.push_back(YMM9);
    registers.push_back(YMM10);
    registers.push_back(YMM11);
    registers.push_back(YMM12);
    registers.push_back(YMM13);
    registers.push_back(YMM14);
    registers.push_back(YMM15);
#endif // AVX512
#else // ENV32BIT
    registers.push_back(EAX);
    registers.push_back(ECX);
    registers.push_back(EDX);

    /*
        registers.push_back(XMM0);
        registers.push_back(XMM1);
        registers.push_back(XMM2);
        registers.push_back(XMM3);
        registers.push_back(XMM4);
        registers.push_back(XMM5);
        registers.push_back(XMM6);
        registers.push_back(XMM7);
     */
#endif
    
    return registers;
}

void Hook::writeSaveScratchRegisters(Assembler& a) const {
    for (const auto& reg : m_ScratchRegisters) {
        writeRegToMem(a, reg);
    }
}

void Hook::writeRestoreScratchRegisters(Assembler& a) const {
    for (const auto& reg : m_ScratchRegisters) {
        writeMemToReg(a, reg);
    }
}

void Hook::writeSaveRegisters(Assembler& a, HookType hookType) const {
    for (const auto& reg : m_Registers) {
        writeRegToMem(a, reg, hookType);
    }
}

void Hook::writeRestoreRegisters(Assembler& a, HookType hookType) const {
    for (const auto& reg : m_Registers) {
        writeMemToReg(a, reg, hookType);
    }
}

void Hook::writeRegToMem(Assembler& a, const Register& reg, HookType hookType) const {
    uintptr_t addr = reg.getAddress<uintptr_t>();
    switch (reg.getType()) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: a.mov(byte_ptr(addr), al); break;
        case CL: a.mov(byte_ptr(addr), cl); break;
        case DL: a.mov(byte_ptr(addr), dl); break;
        case BL: a.mov(byte_ptr(addr), bl); break;

#ifdef ENV64BIT
        case SPL: a.mov(byte_ptr(addr), spl); break;
        case BPL: a.mov(byte_ptr(addr), bpl); break;
        case SIL: a.mov(byte_ptr(addr), sil); break;
        case DIL: a.mov(byte_ptr(addr), dil); break;
        case R8B: a.mov(byte_ptr(addr), r8b); break;
        case R9B: a.mov(byte_ptr(addr), r9b); break;
        case R10B: a.mov(byte_ptr(addr), r10b); break;
        case R11B: a.mov(byte_ptr(addr), r11b); break;
        case R12B: a.mov(byte_ptr(addr), r12b); break;
        case R13B: a.mov(byte_ptr(addr), r13b); break;
        case R14B: a.mov(byte_ptr(addr), r14b); break;
        case R15B: a.mov(byte_ptr(addr), r15b); break;
#endif // ENV64BIT

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

#ifdef ENV64BIT
        case R8W: a.mov(word_ptr(addr), r8w); break;
        case R9W: a.mov(word_ptr(addr), r9w); break;
        case R10W: a.mov(word_ptr(addr), r10w); break;
        case R11W: a.mov(word_ptr(addr), r11w); break;
        case R12W: a.mov(word_ptr(addr), r12w); break;
        case R13W: a.mov(word_ptr(addr), r13w); break;
        case R14W: a.mov(word_ptr(addr), r14w); break;
        case R15W: a.mov(word_ptr(addr), r15w); break;
#endif // ENV64BIT

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

#ifdef ENV64BIT
        case R8D: a.mov(dword_ptr(addr), r8d); break;
        case R9D: a.mov(dword_ptr(addr), r9d); break;
        case R10D: a.mov(dword_ptr(addr), r10d); break;
        case R11D: a.mov(dword_ptr(addr), r11d); break;
        case R12D: a.mov(dword_ptr(addr), r12d); break;
        case R13D: a.mov(dword_ptr(addr), r13d); break;
        case R14D: a.mov(dword_ptr(addr), r14d); break;
        case R15D: a.mov(dword_ptr(addr), r15d); break;
#endif // ENV64BIT

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
#ifdef ENV64BIT
        case RAX: a.mov(qword_ptr(addr), rax); break;
        case RCX: a.mov(qword_ptr(addr), rcx); break;
        case RDX: a.mov(qword_ptr(addr), rdx); break;
        case RBX: a.mov(qword_ptr(addr), rbx); break;
        case RSP: a.mov(qword_ptr(addr), rsp); break;
        case RBP: a.mov(qword_ptr(addr), rbp); break;
        case RSI: a.mov(qword_ptr(addr), rsi); break;
        case RDI: a.mov(qword_ptr(addr), rdi); break;
#endif // ENV64BIT

#ifdef ENV64BIT
        case R8: a.mov(qword_ptr(addr), r8); break;
        case R9: a.mov(qword_ptr(addr), r9); break;
        case R10: a.mov(qword_ptr(addr), r10); break;
        case R11: a.mov(qword_ptr(addr), r11); break;
        case R12: a.mov(qword_ptr(addr), r12); break;
        case R13: a.mov(qword_ptr(addr), r13); break;
        case R14: a.mov(qword_ptr(addr), r14); break;
        case R15: a.mov(qword_ptr(addr), r15); break;
#endif // ENV64BIT

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
#ifdef ENV32BIT
        case XMM0: a.movaps(dqword_ptr(addr), xmm0); break;
        case XMM1: a.movaps(dqword_ptr(addr), xmm1); break;
        case XMM2: a.movaps(dqword_ptr(addr), xmm2); break;
        case XMM3: a.movaps(dqword_ptr(addr), xmm3); break;
        case XMM4: a.movaps(dqword_ptr(addr), xmm4); break;
        case XMM5: a.movaps(dqword_ptr(addr), xmm5); break;
        case XMM6: a.movaps(dqword_ptr(addr), xmm6); break;
        case XMM7: a.movaps(dqword_ptr(addr), xmm7); break;
#else // ENV32BIT
        case XMM0: a.movaps(xmmword_ptr(addr), xmm0); break;
        case XMM1: a.movaps(xmmword_ptr(addr), xmm1); break;
        case XMM2: a.movaps(xmmword_ptr(addr), xmm2); break;
        case XMM3: a.movaps(xmmword_ptr(addr), xmm3); break;
        case XMM4: a.movaps(xmmword_ptr(addr), xmm4); break;
        case XMM5: a.movaps(xmmword_ptr(addr), xmm5); break;
        case XMM6: a.movaps(xmmword_ptr(addr), xmm6); break;
        case XMM7: a.movaps(xmmword_ptr(addr), xmm7); break;
        case XMM8: a.movaps(xmmword_ptr(addr), xmm8); break;
        case XMM9: a.movaps(xmmword_ptr(addr), xmm9); break;
        case XMM10: a.movaps(xmmword_ptr(addr), xmm10); break;
        case XMM11: a.movaps(xmmword_ptr(addr), xmm11); break;
        case XMM12: a.movaps(xmmword_ptr(addr), xmm12); break;
        case XMM13: a.movaps(xmmword_ptr(addr), xmm13); break;
        case XMM14: a.movaps(xmmword_ptr(addr), xmm14); break;
        case XMM15: a.movaps(xmmword_ptr(addr), xmm15); break;
#ifdef AVX512
        case XMM16: a.movaps(xmmword_ptr(addr), xmm16); break;
        case XMM17: a.movaps(xmmword_ptr(addr), xmm17); break;
        case XMM18: a.movaps(xmmword_ptr(addr), xmm18); break;
        case XMM19: a.movaps(xmmword_ptr(addr), xmm19); break;
        case XMM20: a.movaps(xmmword_ptr(addr), xmm20); break;
        case XMM21: a.movaps(xmmword_ptr(addr), xmm21); break;
        case XMM22: a.movaps(xmmword_ptr(addr), xmm22); break;
        case XMM23: a.movaps(xmmword_ptr(addr), xmm23); break;
        case XMM24: a.movaps(xmmword_ptr(addr), xmm24); break;
        case XMM25: a.movaps(xmmword_ptr(addr), xmm25); break;
        case XMM26: a.movaps(xmmword_ptr(addr), xmm26); break;
        case XMM27: a.movaps(xmmword_ptr(addr), xmm27); break;
        case XMM28: a.movaps(xmmword_ptr(addr), xmm28); break;
        case XMM29: a.movaps(xmmword_ptr(addr), xmm29); break;
        case XMM30: a.movaps(xmmword_ptr(addr), xmm30); break;
        case XMM31: a.movaps(xmmword_ptr(addr), xmm31); break;
#endif // AVX512
#endif // ENV32BIT

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#ifdef ENV64BIT
        case YMM0: a.vmovaps(ymmword_ptr(addr), ymm0); break;
        case YMM1: a.vmovaps(ymmword_ptr(addr), ymm1); break;
        case YMM2: a.vmovaps(ymmword_ptr(addr), ymm2); break;
        case YMM3: a.vmovaps(ymmword_ptr(addr), ymm3); break;
        case YMM4: a.vmovaps(ymmword_ptr(addr), ymm4); break;
        case YMM5: a.vmovaps(ymmword_ptr(addr), ymm5); break;
        case YMM6: a.vmovaps(ymmword_ptr(addr), ymm6); break;
        case YMM7: a.vmovaps(ymmword_ptr(addr), ymm7); break;
        case YMM8: a.vmovaps(ymmword_ptr(addr), ymm8); break;
        case YMM9: a.vmovaps(ymmword_ptr(addr), ymm9); break;
        case YMM10: a.vmovaps(ymmword_ptr(addr), ymm10); break;
        case YMM11: a.vmovaps(ymmword_ptr(addr), ymm11); break;
        case YMM12: a.vmovaps(ymmword_ptr(addr), ymm12); break;
        case YMM13: a.vmovaps(ymmword_ptr(addr), ymm13); break;
        case YMM14: a.vmovaps(ymmword_ptr(addr), ymm14); break;
        case YMM15: a.vmovaps(ymmword_ptr(addr), ymm15); break;
#ifdef AVX512
        case YMM16: a.vmovaps(ymmword_ptr(addr), ymm16); break;
        case YMM17: a.vmovaps(ymmword_ptr(addr), ymm17); break;
        case YMM18: a.vmovaps(ymmword_ptr(addr), ymm18); break;
        case YMM19: a.vmovaps(ymmword_ptr(addr), ymm19); break;
        case YMM20: a.vmovaps(ymmword_ptr(addr), ymm20); break;
        case YMM21: a.vmovaps(ymmword_ptr(addr), ymm21); break;
        case YMM22: a.vmovaps(ymmword_ptr(addr), ymm22); break;
        case YMM23: a.vmovaps(ymmword_ptr(addr), ymm23); break;
        case YMM24: a.vmovaps(ymmword_ptr(addr), ymm24); break;
        case YMM25: a.vmovaps(ymmword_ptr(addr), ymm25); break;
        case YMM26: a.vmovaps(ymmword_ptr(addr), ymm26); break;
        case YMM27: a.vmovaps(ymmword_ptr(addr), ymm27); break;
        case YMM28: a.vmovaps(ymmword_ptr(addr), ymm28); break;
        case YMM29: a.vmovaps(ymmword_ptr(addr), ymm29); break;
        case YMM30: a.vmovaps(ymmword_ptr(addr), ymm30); break;
        case YMM31: a.vmovaps(ymmword_ptr(addr), ymm31); break;
#endif // AVX512
#endif // ENV64BIT

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef AVX512
        case ZMM0: a.vmovaps(zmmword_ptr(addr), zmm0); break;
        case ZMM1: a.vmovaps(zmmword_ptr(addr), zmm1); break;
        case ZMM2: a.vmovaps(zmmword_ptr(addr), zmm2); break;
        case ZMM3: a.vmovaps(zmmword_ptr(addr), zmm3); break;
        case ZMM4: a.vmovaps(zmmword_ptr(addr), zmm4); break;
        case ZMM5: a.vmovaps(zmmword_ptr(addr), zmm5); break;
        case ZMM6: a.vmovaps(zmmword_ptr(addr), zmm6); break;
        case ZMM7: a.vmovaps(zmmword_ptr(addr), zmm7); break;
        case ZMM8: a.vmovaps(zmmword_ptr(addr), zmm8); break;
        case ZMM9: a.vmovaps(zmmword_ptr(addr), zmm9); break;
        case ZMM10: a.vmovaps(zmmword_ptr(addr), zmm10); break;
        case ZMM11: a.vmovaps(zmmword_ptr(addr), zmm11); break;
        case ZMM12: a.vmovaps(zmmword_ptr(addr), zmm12); break;
        case ZMM13: a.vmovaps(zmmword_ptr(addr), zmm13); break;
        case ZMM14: a.vmovaps(zmmword_ptr(addr), zmm14); break;
        case ZMM15: a.vmovaps(zmmword_ptr(addr), zmm15); break;
        case ZMM16: a.vmovaps(zmmword_ptr(addr), zmm16); break;
        case ZMM17: a.vmovaps(zmmword_ptr(addr), zmm17); break;
        case ZMM18: a.vmovaps(zmmword_ptr(addr), zmm18); break;
        case ZMM19: a.vmovaps(zmmword_ptr(addr), zmm19); break;
        case ZMM20: a.vmovaps(zmmword_ptr(addr), zmm20); break;
        case ZMM21: a.vmovaps(zmmword_ptr(addr), zmm21); break;
        case ZMM22: a.vmovaps(zmmword_ptr(addr), zmm22); break;
        case ZMM23: a.vmovaps(zmmword_ptr(addr), zmm23); break;
        case ZMM24: a.vmovaps(zmmword_ptr(addr), zmm24); break;
        case ZMM25: a.vmovaps(zmmword_ptr(addr), zmm25); break;
        case ZMM26: a.vmovaps(zmmword_ptr(addr), zmm26); break;
        case ZMM27: a.vmovaps(zmmword_ptr(addr), zmm27); break;
        case ZMM28: a.vmovaps(zmmword_ptr(addr), zmm28); break;
        case ZMM29: a.vmovaps(zmmword_ptr(addr), zmm29); break;
        case ZMM30: a.vmovaps(zmmword_ptr(addr), zmm30); break;
        case ZMM31: a.vmovaps(zmmword_ptr(addr), zmm31); break;
#endif // AVX512

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
#ifdef ENV32BIT
        case ST0:
            // Don't mess with the FPU stack in a pre-hook. The float return is returned in st0,
            // so only load it in a post hook to avoid writing back NaN.
            if (hookType == HookType::Post) {
                switch (m_pCallingConvention->getReturnType().size) {
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
#endif // ENV32BIT

        default: puts("Unsupported register.");
    }
}

void Hook::writeMemToReg(Assembler& a, const Register& reg, HookType hookType) const {
    uintptr_t addr = reg.getAddress<uintptr_t>();
    switch (reg.getType()) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: a.mov(al, byte_ptr(addr)); break;
        case CL: a.mov(cl, byte_ptr(addr)); break;
        case DL: a.mov(dl, byte_ptr(addr)); break;
        case BL: a.mov(bl, byte_ptr(addr)); break;

#ifdef ENV64BIT
        case SPL: a.mov(spl, byte_ptr(addr)); break;
        case BPL: a.mov(bpl, byte_ptr(addr)); break;
        case SIL: a.mov(sil, byte_ptr(addr)); break;
        case DIL: a.mov(dil, byte_ptr(addr)); break;
        case R8B: a.mov(r8b, byte_ptr(addr)); break;
        case R9B: a.mov(r9b, byte_ptr(addr)); break;
        case R10B: a.mov(r10b, byte_ptr(addr)); break;
        case R11B: a.mov(r11b, byte_ptr(addr)); break;
        case R12B: a.mov(r12b, byte_ptr(addr)); break;
        case R13B: a.mov(r13b, byte_ptr(addr)); break;
        case R14B: a.mov(r14b, byte_ptr(addr)); break;
        case R15B: a.mov(r15b, byte_ptr(addr)); break;
#endif // ENV64BIT

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

#ifdef ENV64BIT
        case R8W: a.mov(r8w, word_ptr(addr)); break;
        case R9W: a.mov(r9w, word_ptr(addr)); break;
        case R10W: a.mov(r10w, word_ptr(addr)); break;
        case R11W: a.mov(r11w, word_ptr(addr)); break;
        case R12W: a.mov(r12w, word_ptr(addr)); break;
        case R13W: a.mov(r13w, word_ptr(addr)); break;
        case R14W: a.mov(r14w, word_ptr(addr)); break;
        case R15W: a.mov(r15w, word_ptr(addr)); break;
#endif // ENV64BIT

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

#ifdef ENV64BIT
        case R8D: a.mov(r8d, dword_ptr(addr)); break;
        case R9D: a.mov(r9d, dword_ptr(addr)); break;
        case R10D: a.mov(r10d, dword_ptr(addr)); break;
        case R11D: a.mov(r11d, dword_ptr(addr)); break;
        case R12D: a.mov(r12d, dword_ptr(addr)); break;
        case R13D: a.mov(r13d, dword_ptr(addr)); break;
        case R14D: a.mov(r14d, dword_ptr(addr)); break;
        case R15D: a.mov(r15d, dword_ptr(addr)); break;
#endif // ENV64BIT

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
#ifdef ENV64BIT
        case RAX: a.mov(rax, qword_ptr(addr)); break;
        case RCX: a.mov(rcx, qword_ptr(addr)); break;
        case RDX: a.mov(rdx, qword_ptr(addr)); break;
        case RBX: a.mov(rbx, qword_ptr(addr)); break;
        case RSP: a.mov(rsp, qword_ptr(addr)); break;
        case RBP: a.mov(rbp, qword_ptr(addr)); break;
        case RSI: a.mov(rsi, qword_ptr(addr)); break;
        case RDI: a.mov(rdi, qword_ptr(addr)); break;
#endif // ENV64BIT

#ifdef ENV64BIT
        case R8: a.mov(r8, qword_ptr(addr)); break;
        case R9: a.mov(r9, qword_ptr(addr)); break;
        case R10: a.mov(r10, qword_ptr(addr)); break;
        case R11: a.mov(r11, qword_ptr(addr)); break;
        case R12: a.mov(r12, qword_ptr(addr)); break;
        case R13: a.mov(r13, qword_ptr(addr)); break;
        case R14: a.mov(r14, qword_ptr(addr)); break;
        case R15: a.mov(r15, qword_ptr(addr)); break;
#endif // ENV64BIT

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
#ifdef ENV32BIT
        case XMM0: a.movaps(xmm0, dqword_ptr(addr)); break;
        case XMM1: a.movaps(xmm1, dqword_ptr(addr)); break;
        case XMM2: a.movaps(xmm2, dqword_ptr(addr)); break;
        case XMM3: a.movaps(xmm3, dqword_ptr(addr)); break;
        case XMM4: a.movaps(xmm4, dqword_ptr(addr)); break;
        case XMM5: a.movaps(xmm5, dqword_ptr(addr)); break;
        case XMM6: a.movaps(xmm6, dqword_ptr(addr)); break;
        case XMM7: a.movaps(xmm7, dqword_ptr(addr)); break;
#else // ENV64BIT
        case XMM0: a.movaps(xmm0, xmmword_ptr(addr)); break;
        case XMM1: a.movaps(xmm1, xmmword_ptr(addr)); break;
        case XMM2: a.movaps(xmm2, xmmword_ptr(addr)); break;
        case XMM3: a.movaps(xmm3, xmmword_ptr(addr)); break;
        case XMM4: a.movaps(xmm4, xmmword_ptr(addr)); break;
        case XMM5: a.movaps(xmm5, xmmword_ptr(addr)); break;
        case XMM6: a.movaps(xmm6, xmmword_ptr(addr)); break;
        case XMM7: a.movaps(xmm7, xmmword_ptr(addr)); break;
        case XMM8: a.movaps(xmm8, xmmword_ptr(addr)); break;
        case XMM9: a.movaps(xmm9, xmmword_ptr(addr)); break;
        case XMM10: a.movaps(xmm10, xmmword_ptr(addr)); break;
        case XMM11: a.movaps(xmm11, xmmword_ptr(addr)); break;
        case XMM12: a.movaps(xmm12, xmmword_ptr(addr)); break;
        case XMM13: a.movaps(xmm13, xmmword_ptr(addr)); break;
        case XMM14: a.movaps(xmm14, xmmword_ptr(addr)); break;
        case XMM15: a.movaps(xmm15, xmmword_ptr(addr)); break;
#ifdef AVX512
        case XMM16: a.movaps(xmm16, xmmword_ptr(addr)); break;
        case XMM17: a.movaps(xmm17, xmmword_ptr(addr)); break;
        case XMM18: a.movaps(xmm18, xmmword_ptr(addr)); break;
        case XMM19: a.movaps(xmm19, xmmword_ptr(addr)); break;
        case XMM20: a.movaps(xmm20, xmmword_ptr(addr)); break;
        case XMM21: a.movaps(xmm21, xmmword_ptr(addr)); break;
        case XMM22: a.movaps(xmm22, xmmword_ptr(addr)); break;
        case XMM23: a.movaps(xmm23, xmmword_ptr(addr)); break;
        case XMM24: a.movaps(xmm24, xmmword_ptr(addr)); break;
        case XMM25: a.movaps(xmm25, xmmword_ptr(addr)); break;
        case XMM26: a.movaps(xmm26, xmmword_ptr(addr)); break;
        case XMM27: a.movaps(xmm27, xmmword_ptr(addr)); break;
        case XMM28: a.movaps(xmm28, xmmword_ptr(addr)); break;
        case XMM29: a.movaps(xmm29, xmmword_ptr(addr)); break;
        case XMM30: a.movaps(xmm30, xmmword_ptr(addr)); break;
        case XMM31: a.movaps(xmm31, xmmword_ptr(addr)); break;
#endif // AVX512
#endif // ENV32BIT

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#ifdef ENV64BIT
        case YMM0: a.vmovaps(ymm0, ymmword_ptr(addr)); break;
        case YMM1: a.vmovaps(ymm1, ymmword_ptr(addr)); break;
        case YMM2: a.vmovaps(ymm2, ymmword_ptr(addr)); break;
        case YMM3: a.vmovaps(ymm3, ymmword_ptr(addr)); break;
        case YMM4: a.vmovaps(ymm4, ymmword_ptr(addr)); break;
        case YMM5: a.vmovaps(ymm5, ymmword_ptr(addr)); break;
        case YMM6: a.vmovaps(ymm6, ymmword_ptr(addr)); break;
        case YMM7: a.vmovaps(ymm7, ymmword_ptr(addr)); break;
        case YMM8: a.vmovaps(ymm8, ymmword_ptr(addr)); break;
        case YMM9: a.vmovaps(ymm9, ymmword_ptr(addr)); break;
        case YMM10: a.vmovaps(ymm10, ymmword_ptr(addr)); break;
        case YMM11: a.vmovaps(ymm11, ymmword_ptr(addr)); break;
        case YMM12: a.vmovaps(ymm12, ymmword_ptr(addr)); break;
        case YMM13: a.vmovaps(ymm13, ymmword_ptr(addr)); break;
        case YMM14: a.vmovaps(ymm14, ymmword_ptr(addr)); break;
        case YMM15: a.vmovaps(ymm15, ymmword_ptr(addr)); break;
#ifdef AVX512
        case YMM16: a.vmovaps(ymm16, ymmword_ptr(addr)); break;
        case YMM17: a.vmovaps(ymm17, ymmword_ptr(addr)); break;
        case YMM18: a.vmovaps(ymm18, ymmword_ptr(addr)); break;
        case YMM19: a.vmovaps(ymm19, ymmword_ptr(addr)); break;
        case YMM20: a.vmovaps(ymm20, ymmword_ptr(addr)); break;
        case YMM21: a.vmovaps(ymm21, ymmword_ptr(addr)); break;
        case YMM22: a.vmovaps(ymm22, ymmword_ptr(addr)); break;
        case YMM23: a.vmovaps(ymm23, ymmword_ptr(addr)); break;
        case YMM24: a.vmovaps(ymm24, ymmword_ptr(addr)); break;
        case YMM25: a.vmovaps(ymm25, ymmword_ptr(addr)); break;
        case YMM26: a.vmovaps(ymm26, ymmword_ptr(addr)); break;
        case YMM27: a.vmovaps(ymm27, ymmword_ptr(addr)); break;
        case YMM28: a.vmovaps(ymm28, ymmword_ptr(addr)); break;
        case YMM29: a.vmovaps(ymm29, ymmword_ptr(addr)); break;
        case YMM30: a.vmovaps(ymm30, ymmword_ptr(addr)); break;
        case YMM31: a.vmovaps(ymm31, ymmword_ptr(addr)); break;
#endif // AVX512
#endif // ENV64BIT

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef AVX512
        case ZMM0: a.vmovaps(zmm0, zmmword_ptr(addr)); break;
        case ZMM1: a.vmovaps(zmm1, zmmword_ptr(addr)); break;
        case ZMM2: a.vmovaps(zmm2, zmmword_ptr(addr)); break;
        case ZMM3: a.vmovaps(zmm3, zmmword_ptr(addr)); break;
        case ZMM4: a.vmovaps(zmm4, zmmword_ptr(addr)); break;
        case ZMM5: a.vmovaps(zmm5, zmmword_ptr(addr)); break;
        case ZMM6: a.vmovaps(zmm6, zmmword_ptr(addr)); break;
        case ZMM7: a.vmovaps(zmm7, zmmword_ptr(addr)); break;
        case ZMM8: a.vmovaps(zmm8, zmmword_ptr(addr)); break;
        case ZMM9: a.vmovaps(zmm9, zmmword_ptr(addr)); break;
        case ZMM10: a.vmovaps(zmm10, zmmword_ptr(addr)); break;
        case ZMM11: a.vmovaps(zmm11, zmmword_ptr(addr)); break;
        case ZMM12: a.vmovaps(zmm12, zmmword_ptr(addr)); break;
        case ZMM13: a.vmovaps(zmm13, zmmword_ptr(addr)); break;
        case ZMM14: a.vmovaps(zmm14, zmmword_ptr(addr)); break;
        case ZMM15: a.vmovaps(zmm15, zmmword_ptr(addr)); break;
        case ZMM16: a.vmovaps(zmm16, zmmword_ptr(addr)); break;
        case ZMM17: a.vmovaps(zmm17, zmmword_ptr(addr)); break;
        case ZMM18: a.vmovaps(zmm18, zmmword_ptr(addr)); break;
        case ZMM19: a.vmovaps(zmm19, zmmword_ptr(addr)); break;
        case ZMM20: a.vmovaps(zmm20, zmmword_ptr(addr)); break;
        case ZMM21: a.vmovaps(zmm21, zmmword_ptr(addr)); break;
        case ZMM22: a.vmovaps(zmm22, zmmword_ptr(addr)); break;
        case ZMM23: a.vmovaps(zmm23, zmmword_ptr(addr)); break;
        case ZMM24: a.vmovaps(zmm24, zmmword_ptr(addr)); break;
        case ZMM25: a.vmovaps(zmm25, zmmword_ptr(addr)); break;
        case ZMM26: a.vmovaps(zmm26, zmmword_ptr(addr)); break;
        case ZMM27: a.vmovaps(zmm27, zmmword_ptr(addr)); break;
        case ZMM28: a.vmovaps(zmm28, zmmword_ptr(addr)); break;
        case ZMM29: a.vmovaps(zmm29, zmmword_ptr(addr)); break;
        case ZMM30: a.vmovaps(zmm30, zmmword_ptr(addr)); break;
        case ZMM31: a.vmovaps(zmm31, zmmword_ptr(addr)); break;
#endif // AVX512

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
#ifdef ENV32BIT
        case ST0:
            if (hookType == HookType::Post) {
                // Replace the top of the FPU stack.
                // Copy st0 to st0 and pop -> just pop the FPU stack.
                a.fstp(st0);
                // Push a value to the FPU stack.
                // TODO: Only write back when changed? Save full 80bits for that case.
                //       Avoid truncation of the data if it's unchanged.
                switch (m_pCallingConvention->getReturnType().size) {
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
#endif // ENV32BIT

        default: puts("Unsupported register.");
    }
}