#include "x86MsCdecl.hpp"

#ifdef ENV32BIT

using namespace dyno;

x86MsCdecl::x86MsCdecl(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
        ICallingConvention{std::move(arguments), returnType, alignment} {
    bool nonScalar = m_ReturnType.isFlt();

    // Integer return values up to 32 bits in size are stored in EAX while values up to 64 bit are stored in EAX and EDX.
    // Floating-point return values are similarly stored in ST0.

    if (!nonScalar && m_ReturnType.size > 4)
        m_pReturnBuffer = malloc(m_ReturnType.size);
    else
        m_pReturnBuffer = nullptr;

    if (m_ReturnType.reg == NONE)
        m_ReturnType.reg = nonScalar ? ST0 : EAX;

    init();
}

x86MsCdecl::~x86MsCdecl() {
    if (m_pReturnBuffer)
        free(m_pReturnBuffer);
}

std::vector<RegisterType> x86MsCdecl::getRegisters() {
    std::vector<RegisterType> registers;

    registers.push_back(ESP);

    // Save all the custom calling convention registers as well.
    for (const auto& [type, reg, size] : m_Arguments) {
        if (reg == NONE)
            continue;

        registers.push_back(reg);
    }

    // Save return register as last.
    if (m_pReturnBuffer) {
        registers.push_back(EAX);
        registers.push_back(EDX);
    } else {
        registers.push_back(m_ReturnType.reg);
    }

    return registers;
}

void** x86MsCdecl::getStackArgumentPtr(const Registers& registers) {
    return (void**) (registers[ESP].getValue<uintptr_t>() + 4);
}

void* x86MsCdecl::getArgumentPtr(size_t index, const Registers& registers) {
    if (index >= m_Arguments.size())
        return nullptr;

    // Check if this argument was passed in a register.
    RegisterType regType = m_Arguments[index].reg;
    if (regType != NONE)
        return *registers[regType];

    size_t offset = 4;
    for (size_t i = 0; i < index; ++i) {
        const auto& [type, reg, size] = m_Arguments[i];
        if (reg == NONE)
            offset += size;
    }

    return (void*) (registers[ESP].getValue<uintptr_t>() + offset);
}

void x86MsCdecl::onArgumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) {
}

void* x86MsCdecl::getReturnPtr(const Registers& registers) {
    if (m_pReturnBuffer) {
        // First half in eax, second half in edx
        memcpy(m_pReturnBuffer, *registers.at(EAX, true), 4);
        memcpy((void *) ((uintptr_t) m_pReturnBuffer + 4), *registers.at(EDX, true), 4);
        return m_pReturnBuffer;
    }

    return *registers.at(m_ReturnType.reg, true);
}

void x86MsCdecl::onReturnPtrChanged(const Registers& registers, void* returnPtr) {
    if (m_pReturnBuffer) {
        // First half in eax, second half in edx
        memcpy(*registers.at(EAX, true), m_pReturnBuffer, 4);
        memcpy(*registers.at(EDX, true), (void *) ((uintptr_t) m_pReturnBuffer + 4), 4);
    }
}

#endif // ENV32BIT