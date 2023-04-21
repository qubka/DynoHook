#include "x64MsFastcall.h"

#if DYNO_ARCH_X86 == 64

using namespace dyno;

x64MsFastcall::x64MsFastcall(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
        CallingConvention(std::move(arguments), returnType, alignment) {
    // don't force the register on the user

    RegisterType registers[] = {RCX, RDX, R8, R9 };
    RegisterType sseRegisters[] = {XMM0, XMM1, XMM2, XMM3 };

    size_t argSize = std::min<size_t>(4, m_arguments.size());

    for (size_t i = 0; i < argSize; ++i) {
        DataObject& arg = m_arguments[i];

        // RCX, RDX, R8, R9 for integer, struct or pointer arguments (in that order), and XMM0, XMM1, XMM2, XMM3 for floating point arguments
        if (arg.reg == NONE)
            arg.reg = arg.isFlt() || arg.type == DataType::M128 ? sseRegisters[i] : registers[i];
    }

    if (m_return.reg == NONE)
        m_return.reg = m_return.isFlt() || m_return.type == DataType::M128 ? XMM0 : RAX;

    init();
}

std::vector<RegisterType> x64MsFastcall::getRegisters() {
    std::vector<RegisterType> registers;

    registers.push_back(RSP);

    // save all the custom calling convention registers as well.
    for (const auto& [type, reg, size] : m_arguments) {
        if (reg == NONE)
            continue;

        registers.push_back(reg);
    }

    // save return register as last
    registers.push_back(m_return.reg);

    return registers;
}

void** x64MsFastcall::getStackArgumentPtr(const Registers& registers) {
    return (void**) (registers[RSP].getValue<uintptr_t>() + 8);
}

void* x64MsFastcall::getArgumentPtr(size_t index, const Registers& registers) {
    if (index >= m_arguments.size())
        return nullptr;

    // check if this argument was passed in a register.
    RegisterType regType = m_arguments[index].reg;
    if (regType != NONE)
        return *registers[regType];

    // in the Microsoft x64 calling convention, it is the caller's responsibility to allocate 32 bytes of "shadow space" on the stack right before calling the function (regardless of the actual number of parameters used),
    // and to pop the stack after the call. The shadow space is used to spill RCX, RDX, R8, and R9,[24] but must be made available to all functions, even those with fewer than four parameters.

    size_t offset = 8;
    for (size_t i = 0; i < index; ++i) {
        const auto& [type, reg, size] = m_arguments[i];
        if (reg == NONE)
            offset += size;
        else if (i < 4)
            offset += m_alignment;
    }

    return (void*) (registers[RSP].getValue<uintptr_t>() + offset);
}

void x64MsFastcall::onArgumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) {
}

void* x64MsFastcall::getReturnPtr(const Registers& registers) {
    return *registers.at(m_return.reg, true);
}

void x64MsFastcall::onReturnPtrChanged(const Registers& registers, void* returnPtr) {
}

#endif // DYNO_ARCH_X86