#include "x64SystemVcall.hpp"

#ifdef ENV64BIT

using namespace dyno;

x64SystemVcall::x64SystemVcall(std::vector<DataTypeSized> arguments, DataTypeSized returnType, size_t alignment) :
        ICallingConvention{std::move(arguments), returnType, alignment} {
    // Don't force the register on the user.

    RegisterType registers[] = { RDI, RSI, RDX, RCX, R8, R9 };

    for (size_t i = 0, j = 0, k = 0; i <  m_Arguments.size(); ++i) {
        DataTypeSized& arg = m_Arguments[i];

        if (arg.reg == NONE) {
            // Floating Point Arguments 1-8 ([XYZ]MM0 - [XYZ]MM7)
            if (k < 8 && (arg.isFlt() || arg.isSSE()))
                arg.reg = SSEIndexToRegisterType(k++, arg.size);
            // Integer/Pointer Arguments 1-6 (RDI, RSI, RDX, RCX, R8, R9)
            else if (j < 6)
                arg.reg = registers[j++];
            // Static chain pointer (R10)
            // TODO: Suppose user should provide information about static chain pointer
        }
    }

    bool nonScalar = m_ReturnType.isFlt() || m_ReturnType.isSSE();

    // Integer return values up to 64 bits in size are stored in RAX while values up to 128 bit are stored in RAX and RDX.
    // Floating-point return values are similarly stored in [XYZ]MM0 and [XYZ]MM1. TODO: We used [XYZ]MM0 by default, how we can detect ?

    if (!nonScalar && m_ReturnType.size > 8)
        m_pReturnBuffer = malloc(m_ReturnType.size);
    else
        m_pReturnBuffer = nullptr;

    if (m_ReturnType.reg == NONE)
        m_ReturnType.reg = nonScalar ? SSEIndexToRegisterType(0, m_ReturnType.size) : RAX;

    init();
}

x64SystemVcall::~x64SystemVcall() {
    if (m_pReturnBuffer)
        free(m_pReturnBuffer);
}

std::vector<RegisterType> x64SystemVcall::getRegisters() {
    std::vector<RegisterType> registers;

    registers.push_back(RSP);

    // Save all the custom calling convention registers as well.
    for (const auto& [type, reg, size] : m_Arguments) {
        if (reg == NONE)
            continue;

        registers.push_back(reg);
    }

    // Save return register as last
    if (m_pReturnBuffer) {
        registers.push_back(RAX);
        registers.push_back(RDX);
    } else {
        registers.push_back(m_ReturnType.reg);
    }

    return registers;
}

void** x64SystemVcall::getStackArgumentPtr(const Registers& registers) {
    return (void**) (registers[RSP].getValue<uintptr_t>() + 8);
}

void* x64SystemVcall::getArgumentPtr(size_t index, const Registers& registers) {
    if (index >= m_Arguments.size())
        return nullptr;

    // Check if this argument was passed in a register.
    RegisterType regType = m_Arguments[index].reg;
    if (regType != NONE)
        return *registers[regType];

    size_t offset = 8;
    for (size_t i = 0; i < index; ++i) {
        const auto& [type, reg, size] = m_Arguments[i];
        if (reg == NONE)
            offset += size;
    }

    return (void*) (registers[RSP].getValue<uintptr_t>() + offset);
}

void x64SystemVcall::onArgumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) {
}

void* x64SystemVcall::getReturnPtr(const Registers& registers) {
    if (m_pReturnBuffer) {
        // First half in rax, second half in rdx
        memcpy(m_pReturnBuffer, *registers.at(RAX, true), 8);
        memcpy((void *) ((uintptr_t) m_pReturnBuffer + 8), *registers.at(RDX, true), 8);
        return m_pReturnBuffer;
    }

    return *registers.at(m_ReturnType.reg, true);
}

void x64SystemVcall::onReturnPtrChanged(const Registers& registers, void* returnPtr) {
    if (m_pReturnBuffer) {
        // First half in rax, second half in rdx
        memcpy(*registers.at(RAX, true), m_pReturnBuffer, 8);
        memcpy(*registers.at(RDX, true), (void *) ((uintptr_t) m_pReturnBuffer + 8), 8);
    }
}

#endif // ENV64BIT