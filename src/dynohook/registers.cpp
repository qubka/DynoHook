#include "registers.h"

using namespace dyno;

Register Registers::s_None(NONE, 0);
std::vector<dyno::register_t> Registers::s_Scratch = {
#if DYNO_ARCH_X86 == 64
#ifdef DYNO_PLATFORM_WINDOWS
    RAX,
    RCX,
    RDX,
    R8,
    R9,
    R10,
    R11,
#else // __systemV__
    RAX,
    RDI,
    RSI,
    RDX,
    RCX,
    R8,
    R9,
    R10,
    R11,
#endif
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
// TODO: Do we need to save all sse registers ?
#elif DYNO_ARCH_X86 == 32
    EAX,
    ECX,
    EDX,
#endif // DYNO_ARCH_X86
};

Register::Register(register_t type, size_t size, size_t alignment) : m_size(size), m_alignment(alignment), m_type(type) {
    if (size == 0)
        m_address = nullptr;
    else if (alignment > 0)
#ifdef DYNO_PLATFORM_WINDOWS
        m_address = _aligned_malloc(size, alignment);
#else
        m_address = aligned_alloc(alignment, size);
#endif
    else
        m_address = malloc(size);
}

Register::~Register() {
    if (m_address) {
#ifdef DYNO_PLATFORM_WINDOWS
        if (m_alignment > 0)
            _aligned_free(m_address);
        else
            free(m_address);
#else
        free(m_address);
#endif
    }
}

Register::Register(const Register& other) {
    m_size = other.m_size;
    m_alignment = other.m_alignment;
    m_type = other.m_type;
    if (m_alignment > 0)
#ifdef DYNO_PLATFORM_WINDOWS
        m_address = _aligned_malloc(m_size, m_alignment);
#else
        m_address = aligned_alloc(m_alignment, m_size);
#endif
    else
        m_address = malloc(m_size);
    std::memcpy(m_address, other.m_address, m_size);
}

Register::Register(Register&& other) noexcept {
    m_address = other.m_address;
    m_size = other.m_size;
    m_alignment = other.m_alignment;
    m_type = other.m_type;
    other.m_address = nullptr;
}

Registers::Registers(const std::vector<register_t>& registers) {
    m_registers.reserve(registers.size());

    for (register_t regType : registers) {
        m_registers.emplace_back(regType, RegisterTypeToSize(regType), RegisterTypeToAlignment(regType));
    }
}

const Register& Registers::operator[](register_t regType) const {
    return at(regType);
}

const Register& Registers::at(register_t regType, bool reverse) const {
    if (reverse)
        for (size_t i = m_registers.size() - 1; i != -1; --i) {
            const auto& reg = m_registers[i];
            if (reg == regType)
                return reg;
        }
    else
        for (const auto& reg : m_registers) {
            if (reg == regType)
                return reg;
        }


    return s_None;
}

namespace dyno {

const char* RegisterTypeToName(register_t regType) {
    switch (regType) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: return "AL";
        case CL: return "CL";
        case DL: return "DL";
        case BL: return "BL";

#if DYNO_ARCH_X86 == 64
        case SPL: return "SPL";
        case BPL: return "BPL";
        case SIL: return "SIL";
        case DIL: return "DIL";
        case R8B: return "R8B";
        case R9B: return "R9B";
        case R10B: return "R10B";
        case R11B: return "R11B";
        case R12B: return "R12B";
        case R13B: return "R13B";
        case R14B: return "R14B";
        case R15B: return "R15B";
#endif // DYNO_ARCH_X86

        case AH: return "AH";
        case CH: return "CH";
        case DH: return "DH";
        case BH: return "BH";

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        case AX: return "AX";
        case CX: return "CX";
        case DX: return "DX";
        case BX: return "BX";
        case SP: return "SP";
        case BP: return "BP";
        case SI: return "SI";
        case DI: return "DI";

#if DYNO_ARCH_X86 == 64
        case R8W: return "R8W";
        case R9W: return "R9W";
        case R10W: return "R10W";
        case R11W: return "R11W";
        case R12W: return "R12W";
        case R13W: return "R13W";
        case R14W: return "R14W";
        case R15W: return "R15W";
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        case EAX: return "EAX";
        case ECX: return "ECX";
        case EDX: return "EDX";
        case EBX: return "EBX";
        case ESP: return "ESP";
        case EBP: return "EBP";
        case ESI: return "ESI";
        case EDI: return "EDI";

#if DYNO_ARCH_X86 == 64
        case R8D: return "R8D";
        case R9D: return "R9D";
        case R10D: return "R10D";
        case R11D: return "R11D";
        case R12D: return "R12D";
        case R13D: return "R13D";
        case R14D: return "R14D";
        case R15D: return "R15D";
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
        case RAX: return "RAX";
        case RCX: return "RCX";
        case RDX: return "RDX";
        case RBX: return "RBX";
        case RSP: return "RSP";
        case RBP: return "RBP";
        case RSI: return "RSI";
        case RDI: return "RDI";

        case R8: return "R8";
        case R9: return "R9";
        case R10: return "R10";
        case R11: return "R11";
        case R12: return "R12";
        case R13: return "R13";
        case R14: return "R14";
        case R15: return "R15";
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        case MM0: return "MM0";
        case MM1: return "MM1";
        case MM2: return "MM2";
        case MM3: return "MM3";
        case MM4: return "MM4";
        case MM5: return "MM5";
        case MM6: return "MM6";
        case MM7: return "MM7";

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        case XMM0: return "XMM0";
        case XMM1: return "XMM1";
        case XMM2: return "XMM2";
        case XMM3: return "XMM3";
        case XMM4: return "XMM4";
        case XMM5: return "XMM5";
        case XMM6: return "XMM6";
        case XMM7: return "XMM7";
#if DYNO_ARCH_X86 == 64
        case XMM8: return "XMM8";
        case XMM9: return "XMM9";
        case XMM10: return "XMM10";
        case XMM11: return "XMM11";
        case XMM12: return "XMM12";
        case XMM13: return "XMM13";
        case XMM14: return "XMM14";
        case XMM15: return "XMM15";
#ifdef DYNO_PLATFORM_AVX512
        case XMM16: return "XMM16";
        case XMM17: return "XMM17";
        case XMM18: return "XMM18";
        case XMM19: return "XMM19";
        case XMM20: return "XMM20";
        case XMM21: return "XMM21";
        case XMM22: return "XMM22";
        case XMM23: return "XMM23";
        case XMM24: return "XMM24";
        case XMM25: return "XMM25";
        case XMM26: return "XMM26";
        case XMM27: return "XMM27";
        case XMM28: return "XMM28";
        case XMM29: return "XMM29";
        case XMM30: return "XMM30";
        case XMM31: return "XMM31";
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
        case YMM0: return "YMM0";
        case YMM1: return "YMM1";
        case YMM2: return "YMM2";
        case YMM3: return "YMM3";
        case YMM4: return "YMM4";
        case YMM5: return "YMM5";
        case YMM6: return "YMM6";
        case YMM7: return "YMM7";
        case YMM8: return "YMM8";
        case YMM9: return "YMM9";
        case YMM10: return "YMM10";
        case YMM11: return "YMM11";
        case YMM12: return "YMM12";
        case YMM13: return "YMM13";
        case YMM14: return "YMM14";
        case YMM15: return "YMM15";
#ifdef DYNO_PLATFORM_AVX512
        case YMM16: return "YMM16";
        case YMM17: return "YMM17";
        case YMM18: return "YMM18";
        case YMM19: return "YMM19";
        case YMM20: return "YMM20";
        case YMM21: return "YMM21";
        case YMM22: return "YMM22";
        case YMM23: return "YMM23";
        case YMM24: return "YMM24";
        case YMM25: return "YMM25";
        case YMM26: return "YMM26";
        case YMM27: return "YMM27";
        case YMM28: return "YMM28";
        case YMM29: return "YMM29";
        case YMM30: return "YMM30";
        case YMM31: return "YMM31";
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case ZMM0: return "ZMM0";
        case ZMM1: return "ZMM1";
        case ZMM2: return "ZMM2";
        case ZMM3: return "ZMM3";
        case ZMM4: return "ZMM4";
        case ZMM5: return "ZMM5";
        case ZMM6: return "ZMM6";
        case ZMM7: return "ZMM7";
        case ZMM8: return "ZMM8";
        case ZMM9: return "ZMM9";
        case ZMM10: return "ZMM10";
        case ZMM11: return "ZMM11";
        case ZMM12: return "ZMM12";
        case ZMM13: return "ZMM13";
        case ZMM14: return "ZMM14";
        case ZMM15: return "ZMM15";
        case ZMM16: return "ZMM16";
        case ZMM17: return "ZMM17";
        case ZMM18: return "ZMM18";
        case ZMM19: return "ZMM19";
        case ZMM20: return "ZMM20";
        case ZMM21: return "ZMM21";
        case ZMM22: return "ZMM22";
        case ZMM23: return "ZMM23";
        case ZMM24: return "ZMM24";
        case ZMM25: return "ZMM25";
        case ZMM26: return "ZMM26";
        case ZMM27: return "ZMM27";
        case ZMM28: return "ZMM28";
        case ZMM29: return "ZMM29";
        case ZMM30: return "ZMM30";
        case ZMM31: return "ZMM31";
#endif // DYNO_PLATFORM_AVX512

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        case CS: return "CS";
        case SS: return "SS";
        case DS: return "DS";
        case ES: return "ES";
        case FS: return "FS";
        case GS: return "GS";

        // ========================================================================
        // >> 80-bit FPU registers
        // ========================================================================
#if DYNO_ARCH_X86 == 32
        case ST0: return "ST0";
        case ST1: return "ST1";
        case ST2: return "ST2";
        case ST3: return "ST3";
        case ST4: return "ST4";
        case ST5: return "ST5";
        case ST6: return "ST6";
        case ST7: return "ST7";
#endif // DYNO_ARCH_X86
    }
    return "NONE";
}

size_t RegisterTypeToSize(register_t regType) {
    switch (regType) {
        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        case AL: return SIZE_BYTE;
        case CL: return SIZE_BYTE;
        case DL: return SIZE_BYTE;
        case BL: return SIZE_BYTE;

#if DYNO_ARCH_X86 == 64
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
#endif // DYNO_ARCH_X86

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

#if DYNO_ARCH_X86 == 64
        case R8W: return SIZE_WORD;
        case R9W: return SIZE_WORD;
        case R10W: return SIZE_WORD;
        case R11W: return SIZE_WORD;
        case R12W: return SIZE_WORD;
        case R13W: return SIZE_WORD;
        case R14W: return SIZE_WORD;
        case R15W: return SIZE_WORD;
#endif // DYNO_ARCH_X86

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

#if DYNO_ARCH_X86 == 64
        case R8D: return SIZE_DWORD;
        case R9D: return SIZE_DWORD;
        case R10D: return SIZE_DWORD;
        case R11D: return SIZE_DWORD;
        case R12D: return SIZE_DWORD;
        case R13D: return SIZE_DWORD;
        case R14D: return SIZE_DWORD;
        case R15D: return SIZE_DWORD;
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
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
#endif // DYNO_ARCH_X86

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
#if DYNO_ARCH_X86 == 64
        case XMM8: return SIZE_XMMWORD;
        case XMM9: return SIZE_XMMWORD;
        case XMM10: return SIZE_XMMWORD;
        case XMM11: return SIZE_XMMWORD;
        case XMM12: return SIZE_XMMWORD;
        case XMM13: return SIZE_XMMWORD;
        case XMM14: return SIZE_XMMWORD;
        case XMM15: return SIZE_XMMWORD;
#ifdef DYNO_PLATFORM_AVX512
        case XMM16: return SIZE_XMMWORD;
        case XMM17: return SIZE_XMMWORD;
        case XMM18: return SIZE_XMMWORD;
        case XMM19: return SIZE_XMMWORD;
        case XMM20: return SIZE_XMMWORD;
        case XMM21: return SIZE_XMMWORD;
        case XMM22: return SIZE_XMMWORD;
        case XMM23: return SIZE_XMMWORD;
        case XMM24: return SIZE_XMMWORD;
        case XMM25: return SIZE_XMMWORD;
        case XMM26: return SIZE_XMMWORD;
        case XMM27: return SIZE_XMMWORD;
        case XMM28: return SIZE_XMMWORD;
        case XMM29: return SIZE_XMMWORD;
        case XMM30: return SIZE_XMMWORD;
        case XMM31: return SIZE_XMMWORD;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
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
#ifdef DYNO_PLATFORM_AVX512
        case YMM16: return SIZE_YMMWORD;
        case YMM17: return SIZE_YMMWORD;
        case YMM18: return SIZE_YMMWORD;
        case YMM19: return SIZE_YMMWORD;
        case YMM20: return SIZE_YMMWORD;
        case YMM21: return SIZE_YMMWORD;
        case YMM22: return SIZE_YMMWORD;
        case YMM23: return SIZE_YMMWORD;
        case YMM24: return SIZE_YMMWORD;
        case YMM25: return SIZE_YMMWORD;
        case YMM26: return SIZE_YMMWORD;
        case YMM27: return SIZE_YMMWORD;
        case YMM28: return SIZE_YMMWORD;
        case YMM29: return SIZE_YMMWORD;
        case YMM30: return SIZE_YMMWORD;
        case YMM31: return SIZE_YMMWORD;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case ZMM0: return SIZE_ZMMWORD;
        case ZMM1: return SIZE_ZMMWORD;
        case ZMM2: return SIZE_ZMMWORD;
        case ZMM3: return SIZE_ZMMWORD;
        case ZMM4: return SIZE_ZMMWORD;
        case ZMM5: return SIZE_ZMMWORD;
        case ZMM6: return SIZE_ZMMWORD;
        case ZMM7: return SIZE_ZMMWORD;
        case ZMM8: return SIZE_ZMMWORD;
        case ZMM9: return SIZE_ZMMWORD;
        case ZMM10: return SIZE_ZMMWORD;
        case ZMM11: return SIZE_ZMMWORD;
        case ZMM12: return SIZE_ZMMWORD;
        case ZMM13: return SIZE_ZMMWORD;
        case ZMM14: return SIZE_ZMMWORD;
        case ZMM15: return SIZE_ZMMWORD;
        case ZMM16: return SIZE_ZMMWORD;
        case ZMM17: return SIZE_ZMMWORD;
        case ZMM18: return SIZE_ZMMWORD;
        case ZMM19: return SIZE_ZMMWORD;
        case ZMM20: return SIZE_ZMMWORD;
        case ZMM21: return SIZE_ZMMWORD;
        case ZMM22: return SIZE_ZMMWORD;
        case ZMM23: return SIZE_ZMMWORD;
        case ZMM24: return SIZE_ZMMWORD;
        case ZMM25: return SIZE_ZMMWORD;
        case ZMM26: return SIZE_ZMMWORD;
        case ZMM27: return SIZE_ZMMWORD;
        case ZMM28: return SIZE_ZMMWORD;
        case ZMM29: return SIZE_ZMMWORD;
        case ZMM30: return SIZE_ZMMWORD;
        case ZMM31: return SIZE_ZMMWORD;
#endif // DYNO_PLATFORM_AVX512

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
#if DYNO_ARCH_X86 == 32
        case ST0: return SIZE_TWORD;
        case ST1: return SIZE_TWORD;
        case ST2: return SIZE_TWORD;
        case ST3: return SIZE_TWORD;
        case ST4: return SIZE_TWORD;
        case ST5: return SIZE_TWORD;
        case ST6: return SIZE_TWORD;
        case ST7: return SIZE_TWORD;
#endif // DYNO_ARCH_X86
    }
    return 0;
}

size_t RegisterTypeToAlignment(register_t regType) {
    switch (regType) {
        /**
         * The primary exceptions are the stack pointer, which are 16-byte aligned to aid performance.
         */
#if DYNO_ARCH_X86 == 64
        case RSP: return SIZE_XMMWORD;
#endif // DYNO_ARCH_X86

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
#if DYNO_ARCH_X86 == 64
        case XMM8: return SIZE_XMMWORD;
        case XMM9: return SIZE_XMMWORD;
        case XMM10: return SIZE_XMMWORD;
        case XMM11: return SIZE_XMMWORD;
        case XMM12: return SIZE_XMMWORD;
        case XMM13: return SIZE_XMMWORD;
        case XMM14: return SIZE_XMMWORD;
        case XMM15: return SIZE_XMMWORD;
#ifdef DYNO_PLATFORM_AVX512
        case XMM16: return SIZE_XMMWORD;
        case XMM17: return SIZE_XMMWORD;
        case XMM18: return SIZE_XMMWORD;
        case XMM19: return SIZE_XMMWORD;
        case XMM20: return SIZE_XMMWORD;
        case XMM21: return SIZE_XMMWORD;
        case XMM22: return SIZE_XMMWORD;
        case XMM23: return SIZE_XMMWORD;
        case XMM24: return SIZE_XMMWORD;
        case XMM25: return SIZE_XMMWORD;
        case XMM26: return SIZE_XMMWORD;
        case XMM27: return SIZE_XMMWORD;
        case XMM28: return SIZE_XMMWORD;
        case XMM29: return SIZE_XMMWORD;
        case XMM30: return SIZE_XMMWORD;
        case XMM31: return SIZE_XMMWORD;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
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
#ifdef DYNO_PLATFORM_AVX512
        case YMM16: return SIZE_YMMWORD;
        case YMM17: return SIZE_YMMWORD;
        case YMM18: return SIZE_YMMWORD;
        case YMM19: return SIZE_YMMWORD;
        case YMM20: return SIZE_YMMWORD;
        case YMM21: return SIZE_YMMWORD;
        case YMM22: return SIZE_YMMWORD;
        case YMM23: return SIZE_YMMWORD;
        case YMM24: return SIZE_YMMWORD;
        case YMM25: return SIZE_YMMWORD;
        case YMM26: return SIZE_YMMWORD;
        case YMM27: return SIZE_YMMWORD;
        case YMM28: return SIZE_YMMWORD;
        case YMM29: return SIZE_YMMWORD;
        case YMM30: return SIZE_YMMWORD;
        case YMM31: return SIZE_YMMWORD;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case ZMM0: return SIZE_ZMMWORD;
        case ZMM1: return SIZE_ZMMWORD;
        case ZMM2: return SIZE_ZMMWORD;
        case ZMM3: return SIZE_ZMMWORD;
        case ZMM4: return SIZE_ZMMWORD;
        case ZMM5: return SIZE_ZMMWORD;
        case ZMM6: return SIZE_ZMMWORD;
        case ZMM7: return SIZE_ZMMWORD;
        case ZMM8: return SIZE_ZMMWORD;
        case ZMM9: return SIZE_ZMMWORD;
        case ZMM10: return SIZE_ZMMWORD;
        case ZMM11: return SIZE_ZMMWORD;
        case ZMM12: return SIZE_ZMMWORD;
        case ZMM13: return SIZE_ZMMWORD;
        case ZMM14: return SIZE_ZMMWORD;
        case ZMM15: return SIZE_ZMMWORD;
        case ZMM16: return SIZE_ZMMWORD;
        case ZMM17: return SIZE_ZMMWORD;
        case ZMM18: return SIZE_ZMMWORD;
        case ZMM19: return SIZE_ZMMWORD;
        case ZMM20: return SIZE_ZMMWORD;
        case ZMM21: return SIZE_ZMMWORD;
        case ZMM22: return SIZE_ZMMWORD;
        case ZMM23: return SIZE_ZMMWORD;
        case ZMM24: return SIZE_ZMMWORD;
        case ZMM25: return SIZE_ZMMWORD;
        case ZMM26: return SIZE_ZMMWORD;
        case ZMM27: return SIZE_ZMMWORD;
        case ZMM28: return SIZE_ZMMWORD;
        case ZMM29: return SIZE_ZMMWORD;
        case ZMM30: return SIZE_ZMMWORD;
        case ZMM31: return SIZE_ZMMWORD;
#endif // DYNO_PLATFORM_AVX512
    }
    return 0;
}

size_t RegisterTypeToSSEIndex(register_t regType) {
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
#if DYNO_ARCH_X86 == 64
        case XMM8: return 8;
        case XMM9: return 9;
        case XMM10: return 10;
        case XMM11: return 11;
        case XMM12: return 12;
        case XMM13: return 13;
        case XMM14: return 14;
        case XMM15: return 15;
#ifdef DYNO_PLATFORM_AVX512
        case XMM16: return 16;
        case XMM17: return 17;
        case XMM18: return 18;
        case XMM19: return 19;
        case XMM20: return 20;
        case XMM21: return 21;
        case XMM22: return 22;
        case XMM23: return 23;
        case XMM24: return 24;
        case XMM25: return 25;
        case XMM26: return 26;
        case XMM27: return 27;
        case XMM28: return 28;
        case XMM29: return 29;
        case XMM30: return 30;
        case XMM31: return 31;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
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
#ifdef DYNO_PLATFORM_AVX512
        case YMM16: return 16;
        case YMM17: return 17;
        case YMM18: return 18;
        case YMM19: return 19;
        case YMM20: return 20;
        case YMM21: return 21;
        case YMM22: return 22;
        case YMM23: return 23;
        case YMM24: return 24;
        case YMM25: return 25;
        case YMM26: return 26;
        case YMM27: return 27;
        case YMM28: return 28;
        case YMM29: return 29;
        case YMM30: return 30;
        case YMM31: return 31;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case ZMM0: return 0;
        case ZMM1: return 1;
        case ZMM2: return 2;
        case ZMM3: return 3;
        case ZMM4: return 4;
        case ZMM5: return 5;
        case ZMM6: return 6;
        case ZMM7: return 7;
        case ZMM8: return 8;
        case ZMM9: return 9;
        case ZMM10: return 10;
        case ZMM11: return 11;
        case ZMM12: return 12;
        case ZMM13: return 13;
        case ZMM14: return 14;
        case ZMM15: return 15;
        case ZMM16: return 16;
        case ZMM17: return 17;
        case ZMM18: return 18;
        case ZMM19: return 19;
        case ZMM20: return 20;
        case ZMM21: return 21;
        case ZMM22: return 22;
        case ZMM23: return 23;
        case ZMM24: return 24;
        case ZMM25: return 25;
        case ZMM26: return 26;
        case ZMM27: return 27;
        case ZMM28: return 28;
        case ZMM29: return 29;
        case ZMM30: return 30;
        case ZMM31: return 31;
#endif // DYNO_PLATFORM_AVX512
    }
    return -1;
}

register_t SSEIndexToRegisterType(size_t index, size_t size) {
    switch (size) {
        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        default:
            switch (index) {
                case 0: return XMM0;
                case 1: return XMM1;
                case 2: return XMM2;
                case 3: return XMM3;
                case 4: return XMM4;
                case 5: return XMM5;
                case 6: return XMM6;
                case 7: return XMM7;
#if DYNO_ARCH_X86 == 64
                case 8: return XMM8;
                case 9: return XMM9;
                case 10: return XMM10;
                case 11: return XMM11;
                case 12: return XMM12;
                case 13: return XMM13;
                case 14: return XMM14;
                case 15: return XMM15;
#ifdef DYNO_PLATFORM_AVX512
                case 16: return XMM16;
                case 17: return XMM17;
                case 18: return XMM18;
                case 19: return XMM19;
                case 20: return XMM20;
                case 21: return XMM21;
                case 22: return XMM22;
                case 23: return XMM23;
                case 24: return XMM24;
                case 25: return XMM25;
                case 26: return XMM26;
                case 27: return XMM27;
                case 28: return XMM28;
                case 29: return XMM29;
                case 30: return XMM30;
                case 31: return XMM31;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86
            }
            break;

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#if DYNO_ARCH_X86 == 64
        case SIZE_YMMWORD:
            switch (index) {
                case 0: return YMM0;
                case 1: return YMM1;
                case 2: return YMM2;
                case 3: return YMM3;
                case 4: return YMM4;
                case 5: return YMM5;
                case 6: return YMM6;
                case 7: return YMM7;
                case 8: return YMM8;
                case 9: return YMM9;
                case 10: return YMM10;
                case 11: return YMM11;
                case 12: return YMM12;
                case 13: return YMM13;
                case 14: return YMM14;
                case 15: return YMM15;
#ifdef DYNO_PLATFORM_AVX512
                case 16: return YMM16;
                case 17: return YMM17;
                case 18: return YMM18;
                case 19: return YMM19;
                case 20: return YMM20;
                case 21: return YMM21;
                case 22: return YMM22;
                case 23: return YMM23;
                case 24: return YMM24;
                case 25: return YMM25;
                case 26: return YMM26;
                case 27: return YMM27;
                case 28: return YMM28;
                case 29: return YMM29;
                case 30: return YMM30;
                case 31: return YMM31;
#endif // DYNO_PLATFORM_AVX512
            }
            break;
#endif // DYNO_ARCH_X86

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
        case SIZE_ZMMWORD:
            switch (index) {
                case 0: return ZMM0;
                case 1: return ZMM1;
                case 2: return ZMM2;
                case 3: return ZMM3;
                case 4: return ZMM4;
                case 5: return ZMM5;
                case 6: return ZMM6;
                case 7: return ZMM7;
                case 8: return ZMM8;
                case 9: return ZMM9;
                case 10: return ZMM10;
                case 11: return ZMM11;
                case 12: return ZMM12;
                case 13: return ZMM13;
                case 14: return ZMM14;
                case 15: return ZMM15;
                case 16: return ZMM16;
                case 17: return ZMM17;
                case 18: return ZMM18;
                case 19: return ZMM19;
                case 20: return ZMM20;
                case 21: return ZMM21;
                case 22: return ZMM22;
                case 23: return ZMM23;
                case 24: return ZMM24;
                case 25: return ZMM25;
                case 26: return ZMM26;
                case 27: return ZMM27;
                case 28: return ZMM28;
                case 29: return ZMM29;
                case 30: return ZMM30;
                case 31: return ZMM31;
            }
            break;
#endif // DYNO_PLATFORM_AVX512
    }
    return NONE;
}

std::ostream& operator<<(std::ostream& os, register_t v) {
    os << RegisterTypeToName(v);
    return os;
}

}
