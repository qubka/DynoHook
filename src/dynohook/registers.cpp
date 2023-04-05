#include "registers.hpp"

using namespace dyno;

Registers::Registers(const std::vector<RegisterType>& registers) {
    m_Registers.reserve(registers.size());

    for (RegisterType regType : registers) {
        m_Registers.emplace_back(regType, TypeToSize(regType), TypeToAlignment(regType));
    }
}

const Register& Registers::operator[](RegisterType regType) const {
    return at(regType);
}

const Register& Registers::at(RegisterType regType, bool reverse) const {
    static Register s_None{NONE, 0};

    if (reverse) {
        for (size_t i = m_Registers.size() - 1; i != -1; --i) {
            const auto& reg = m_Registers[i];
            if (reg.getType() == regType) {
                return reg;
            }
        }
    } else {
        for (const auto& reg : m_Registers) {
            if (reg.getType() == regType) {
                return reg;
            }
        }
    }

    return s_None;
}

size_t dyno::TypeToSize(RegisterType regType) {
    switch (regType) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: return SIZE_BYTE;
        case CL: return SIZE_BYTE;
        case DL: return SIZE_BYTE;
        case BL: return SIZE_BYTE;

#ifdef ENV64BIT
        case SPL: return SIZE_BYTE;
        case BPL: return SIZE_BYTE;
        case SIL: return SIZE_BYTE;
        case DIL: return SIZE_BYTE;
        case R8B: return SIZE_BYTE;
        case R9B: return SIZE_BYTE;
        case R10B: return SIZE_BYTE;
        case R11B: return SIZE_BYTE;
        case R12B: return SIZE_BYTE;
        case R13B: return SIZE_BYTE;
        case R14B: return SIZE_BYTE;
        case R15B: return SIZE_BYTE;
#endif

        case AH: return SIZE_BYTE;
        case CH: return SIZE_BYTE;
        case DH: return SIZE_BYTE;
        case BH: return SIZE_BYTE;

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        case AX: return SIZE_WORD;
        case CX: return SIZE_WORD;
        case DX: return SIZE_WORD;
        case BX: return SIZE_WORD;
        case SP: return SIZE_WORD;
        case BP: return SIZE_WORD;
        case SI: return SIZE_WORD;
        case DI: return SIZE_WORD;

#ifdef ENV64BIT
        case R8W: return SIZE_WORD;
        case R9W: return SIZE_WORD;
        case R10W: return SIZE_WORD;
        case R11W: return SIZE_WORD;
        case R12W: return SIZE_WORD;
        case R13W: return SIZE_WORD;
        case R14W: return SIZE_WORD;
        case R15W: return SIZE_WORD;
#endif

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        case EAX: return SIZE_DWORD;
        case ECX: return SIZE_DWORD;
        case EDX: return SIZE_DWORD;
        case EBX: return SIZE_DWORD;
        case ESP: return SIZE_DWORD;
        case EBP: return SIZE_DWORD;
        case ESI: return SIZE_DWORD;
        case EDI: return SIZE_DWORD;

#ifdef ENV64BIT
        case R8D: return SIZE_DWORD;
        case R9D: return SIZE_DWORD;
        case R10D: return SIZE_DWORD;
        case R11D: return SIZE_DWORD;
        case R12D: return SIZE_DWORD;
        case R13D: return SIZE_DWORD;
        case R14D: return SIZE_DWORD;
        case R15D: return SIZE_DWORD;
#endif

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
#ifdef ENV64BIT
        case RAX: return SIZE_QWORD;
        case RCX: return SIZE_QWORD;
        case RDX: return SIZE_QWORD;
        case RBX: return SIZE_QWORD;
        case RSP: return SIZE_QWORD;
        case RBP: return SIZE_QWORD;
        case RSI: return SIZE_QWORD;
        case RDI: return SIZE_QWORD;

        case R8: return SIZE_QWORD;
        case R9: return SIZE_QWORD;
        case R10: return SIZE_QWORD;
        case R11: return SIZE_QWORD;
        case R12: return SIZE_QWORD;
        case R13: return SIZE_QWORD;
        case R14: return SIZE_QWORD;
        case R15: return SIZE_QWORD;
#endif

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        case MM0: return SIZE_QWORD;
        case MM1: return SIZE_QWORD;
        case MM2: return SIZE_QWORD;
        case MM3: return SIZE_QWORD;
        case MM4: return SIZE_QWORD;
        case MM5: return SIZE_QWORD;
        case MM6: return SIZE_QWORD;
        case MM7: return SIZE_QWORD;

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: return SIZE_XMMWORD;
        case XMM1: return SIZE_XMMWORD;
        case XMM2: return SIZE_XMMWORD;
        case XMM3: return SIZE_XMMWORD;
        case XMM4: return SIZE_XMMWORD;
        case XMM5: return SIZE_XMMWORD;
        case XMM6: return SIZE_XMMWORD;
        case XMM7: return SIZE_XMMWORD;

#ifdef ENV64BIT
        case XMM8: return SIZE_XMMWORD;
        case XMM9: return SIZE_XMMWORD;
        case XMM10: return SIZE_XMMWORD;
        case XMM11: return SIZE_XMMWORD;
        case XMM12: return SIZE_XMMWORD;
        case XMM13: return SIZE_XMMWORD;
        case XMM14: return SIZE_XMMWORD;
        case XMM15: return SIZE_XMMWORD;
#endif

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#ifdef ENV64BIT
        case YMM0: return SIZE_YMMWORD;
        case YMM1: return SIZE_YMMWORD;
        case YMM2: return SIZE_YMMWORD;
        case YMM3: return SIZE_YMMWORD;
        case YMM4: return SIZE_YMMWORD;
        case YMM5: return SIZE_YMMWORD;
        case YMM6: return SIZE_YMMWORD;
        case YMM7: return SIZE_YMMWORD;
        case YMM8: return SIZE_YMMWORD;
        case YMM9: return SIZE_YMMWORD;
        case YMM10: return SIZE_YMMWORD;
        case YMM11: return SIZE_YMMWORD;
        case YMM12: return SIZE_YMMWORD;
        case YMM13: return SIZE_YMMWORD;
        case YMM14: return SIZE_YMMWORD;
        case YMM15: return SIZE_YMMWORD;
#endif

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        case CS: return SIZE_WORD;
        case SS: return SIZE_WORD;
        case DS: return SIZE_WORD;
        case ES: return SIZE_WORD;
        case FS: return SIZE_WORD;
        case GS: return SIZE_WORD;

        // ========================================================================
        // >> 80-bit FPU registers
        // ========================================================================
#ifdef ENV32BIT
        case ST0: return SIZE_TWORD;
        case ST1: return SIZE_TWORD;
        case ST2: return SIZE_TWORD;
        case ST3: return SIZE_TWORD;
        case ST4: return SIZE_TWORD;
        case ST5: return SIZE_TWORD;
        case ST6: return SIZE_TWORD;
        case ST7: return SIZE_TWORD;
#endif
    }
    return 0;
}

size_t dyno::TypeToAlignment(RegisterType regType) {
    switch (regType) {
        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: return SIZE_XMMWORD;
        case XMM1: return SIZE_XMMWORD;
        case XMM2: return SIZE_XMMWORD;
        case XMM3: return SIZE_XMMWORD;
        case XMM4: return SIZE_XMMWORD;
        case XMM5: return SIZE_XMMWORD;
        case XMM6: return SIZE_XMMWORD;
        case XMM7: return SIZE_XMMWORD;

#ifdef ENV64BIT
        case XMM8: return SIZE_XMMWORD;
        case XMM9: return SIZE_XMMWORD;
        case XMM10: return SIZE_XMMWORD;
        case XMM11: return SIZE_XMMWORD;
        case XMM12: return SIZE_XMMWORD;
        case XMM13: return SIZE_XMMWORD;
        case XMM14: return SIZE_XMMWORD;
        case XMM15: return SIZE_XMMWORD;
#endif

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#ifdef ENV64BIT
        case YMM0: return SIZE_YMMWORD;
        case YMM1: return SIZE_YMMWORD;
        case YMM2: return SIZE_YMMWORD;
        case YMM3: return SIZE_YMMWORD;
        case YMM4: return SIZE_YMMWORD;
        case YMM5: return SIZE_YMMWORD;
        case YMM6: return SIZE_YMMWORD;
        case YMM7: return SIZE_YMMWORD;
        case YMM8: return SIZE_YMMWORD;
        case YMM9: return SIZE_YMMWORD;
        case YMM10: return SIZE_YMMWORD;
        case YMM11: return SIZE_YMMWORD;
        case YMM12: return SIZE_YMMWORD;
        case YMM13: return SIZE_YMMWORD;
        case YMM14: return SIZE_YMMWORD;
        case YMM15: return SIZE_YMMWORD;
#endif
    }
    return 0;
}

size_t dyno::TypeToIndex(RegisterType regType) {
    switch (regType) {
        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: return 0;
        case XMM1: return 1;
        case XMM2: return 2;
        case XMM3: return 3;
        case XMM4: return 4;
        case XMM5: return 5;
        case XMM6: return 6;
        case XMM7: return 7;

#ifdef ENV64BIT
        case XMM8: return 8;
        case XMM9: return 9;
        case XMM10: return 10;
        case XMM11: return 11;
        case XMM12: return 12;
        case XMM13: return 13;
        case XMM14: return 14;
        case XMM15: return 15;
#endif

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#ifdef ENV64BIT
        case YMM0: return 0;
        case YMM1: return 1;
        case YMM2: return 2;
        case YMM3: return 3;
        case YMM4: return 4;
        case YMM5: return 5;
        case YMM6: return 6;
        case YMM7: return 7;
        case YMM8: return 8;
        case YMM9: return 9;
        case YMM10: return 10;
        case YMM11: return 11;
        case YMM12: return 12;
        case YMM13: return 13;
        case YMM14: return 14;
        case YMM15: return 15;
#endif

        // ========================================================================
        // >> 80-bit FPU registers
        // ========================================================================
#ifdef ENV32BIT
        case ST0: return 0;
        case ST1: return 1;
        case ST2: return 2;
        case ST3: return 3;
        case ST4: return 4;
        case ST5: return 5;
        case ST6: return 6;
        case ST7: return 7;
#endif
    }
    return 0;
}