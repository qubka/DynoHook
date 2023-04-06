#include "x64MsStdcall.hpp"

#ifdef ENV64BIT

using namespace dyno;

x64MsStdcall::x64MsStdcall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
        ICallingConvention{std::move(arguments), returnType, alignment} {

    RegisterType registers[] = { RCX, RDX, R8, R9 };
    RegisterType xmmRegisters[] = { XMM0, XMM1, XMM2, XMM3 };

    size_t argSize = std::min(4, (int) m_Arguments.size());

    for (size_t i = 0; i < argSize; ++i) {
        DataTypeSized& type = m_Arguments[i];

        if (type.reg == NONE) {
            type.reg = type.isFloating() ? xmmRegisters[i] : registers[i];
        }
    }

    init();
}

x64MsStdcall::~x64MsStdcall() {
}

std::vector<RegisterType> x64MsStdcall::getRegisters() {
    std::vector<RegisterType> registers;

    registers.push_back(RSP);

    // Save all the custom calling convention registers as well.
    for (const auto& [type, reg, size] : m_Arguments) {
        if (reg == NONE)
            continue;

        registers.push_back(reg);
    }

    // Save return register as last
    if (m_ReturnType.isFloating() || m_ReturnType.type == DATA_TYPE_M128) {
        registers.push_back(XMM0);
    } else
        registers.push_back(RAX);

    return registers;
}

void** x64MsStdcall::getStackArgumentPtr(const Registers& registers) {
    return (void**) (registers[RSP].getValue<uintptr_t>() + 8);
}

void* x64MsStdcall::getArgumentPtr(size_t index, const Registers& registers) {
    if (index >= m_Arguments.size())
        return nullptr;

    // Check if this argument was passed in a register.
    RegisterType regType = m_Arguments[index].reg;
    if (regType != NONE)
        return *registers[regType];

    // In the Microsoft x64 calling convention, it is the caller's responsibility to allocate 32 bytes of "shadow space" on the stack right before calling the function (regardless of the actual number of parameters used),
    // and to pop the stack after the call. The shadow space is used to spill RCX, RDX, R8, and R9,[24] but must be made available to all functions, even those with fewer than four parameters.

    size_t offset = 8;
    for (size_t i = 0; i < index; ++i) {
        const auto& [type, reg, size] = m_Arguments[i];
        if (reg == NONE)
            offset += size;
        else if (i < 4)
            offset += m_iAlignment;
    }

    return (void*) (registers[RSP].getValue<uintptr_t>() + offset);
}

void* x64MsStdcall::getReturnPtr(const Registers& registers) {
    bool nonScalar = m_ReturnType.isFloating() || m_ReturnType.type == DATA_TYPE_M128;
    return *registers.at(nonScalar ? XMM0 : RAX, true);
}

#endif // ENV64BIT