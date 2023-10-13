#include "x86MsCdecl.h"

using namespace dyno;

x86MsCdecl::x86MsCdecl(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
        CallingConvention{std::move(arguments), returnType, alignment} {
    bool nonScalar = m_return.isFlt();

    // integer return values up to 32 bits in size are stored in EAX while values up to 64 bit are stored in EAX and EDX.
    // floating-point return values are similarly stored in ST0.

    if (!nonScalar && m_return.size > 4)
        m_returnBuffer = malloc(m_return.size);
    else
        m_returnBuffer = nullptr;

    if (m_return.reg == NONE)
        m_return.reg = nonScalar ? ST0 : EAX;

    init();
}

x86MsCdecl::~x86MsCdecl() {
    if (m_returnBuffer)
        free(m_returnBuffer);
}

regs_t x86MsCdecl::getRegisters() {
    regs_t registers;

    registers.push_back(ESP);

    // save all the custom calling convention registers as well
    for (const auto& [type, reg, size] : m_arguments) {
        if (reg == NONE)
            continue;

        registers.push_back(reg);
    }

    // save return register as last
    if (m_returnBuffer) {
        registers.push_back(EAX);
        registers.push_back(EDX);
    } else {
        registers.push_back(m_return.reg);
    }

    return registers;
}

void** x86MsCdecl::getStackArgumentPtr(const Registers& registers) {
    return (void**) (registers[ESP].getValue<uintptr_t>() + 4);
}

void* x86MsCdecl::getArgumentPtr(size_t index, const Registers& registers) {
    if (index >= m_arguments.size())
        return nullptr;

    // check if this argument was passed in a register.
    RegisterType regType = m_arguments[index].reg;
    if (regType != NONE)
        return *registers[regType];

    size_t offset = 4;
    for (size_t i = 0; i < index; i++) {
        const auto& [type, reg, size] = m_arguments[i];
        if (reg == NONE)
            offset += size;
    }

    return (void*) (registers[ESP].getValue<uintptr_t>() + offset);
}

void x86MsCdecl::onArgumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) {
}

void* x86MsCdecl::getReturnPtr(const Registers& registers) {
    if (m_returnBuffer) {
        // first half in eax, second half in edx
        std::memcpy(m_returnBuffer, *registers.at(EAX, true), 4);
        std::memcpy((uint8_t*) m_returnBuffer + 4, *registers.at(EDX, true), 4);
        return m_returnBuffer;
    }

    return *registers.at(m_return.reg, true);
}

void x86MsCdecl::onReturnPtrChanged(const Registers& registers, void* returnPtr) {
    if (m_returnBuffer) {
        // first half in eax, second half in edx
        std::memcpy(*registers.at(EAX, true), m_returnBuffer, 4);
        std::memcpy(*registers.at(EDX, true), (uint8_t*) m_returnBuffer + 4, 4);
    }
}