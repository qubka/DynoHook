#include "registers.h"

using namespace dyno;

Register Registers::s_None(NONE, SIZE_INVALID);
std::vector<RegisterType> Registers::s_Scratch = {
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
#ifndef DYNO_PLATFORM_WINDOWS
    XMM6,
    XMM7,
#endif
// TODO: Do we need to save all sse registers ?
#elif DYNO_ARCH_X86 == 32
    EAX,
    ECX,
    EDX,
#endif // DYNO_ARCH_X86
};

Register::Register(RegisterType type, RegisterSize size, uint8_t alignment) : m_type(type), m_size(size), m_alignment(alignment) {
    if (m_size == 0)
        m_address = nullptr;
    else if (m_alignment > 0)
#ifdef DYNO_PLATFORM_WINDOWS
        m_address = _aligned_malloc(m_size, m_alignment);
#else
        m_address = aligned_alloc(alignment, size);
#endif
    else
        m_address = malloc(m_size);
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
    m_type = other.m_type;
    m_size = other.m_size;
    m_alignment = other.m_alignment;
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
    m_type = other.m_type;
    m_size = other.m_size;
    m_alignment = other.m_alignment;
    other.m_address = nullptr;
}

std::array<RegisterInfo, REG_COUNT> s_RegisterTable = {{
    {"NONE", SIZE_INVALID, 0 },

    // ========================================================================
    // >> 8-bit General purpose registers
    // ========================================================================
    {"AL", SIZE_BYTE, 0 },
    {"CL", SIZE_BYTE, 0 },
    {"DL", SIZE_BYTE, 0 },
    {"BL", SIZE_BYTE, 0 },

#if DYNO_ARCH_X86 == 64
    {"SPL", SIZE_BYTE, 0 },
    {"BPL", SIZE_BYTE, 0 },
    {"SIL", SIZE_BYTE, 0 },
    {"DIL", SIZE_BYTE, 0 },
    {"R8B", SIZE_BYTE, 0 },
    {"R9B", SIZE_BYTE, 0 },
    {"R10B", SIZE_BYTE, 0 },
    {"R11B", SIZE_BYTE, 0 },
    {"R12B", SIZE_BYTE, 0 },
    {"R13B", SIZE_BYTE, 0 },
    {"R14B", SIZE_BYTE, 0 },
    {"R15B", SIZE_BYTE, 0 },
#endif // DYNO_ARCH_X86

    {"AH", SIZE_BYTE, 0 },
    {"CH", SIZE_BYTE, 0 },
    {"DH", SIZE_BYTE, 0 },
    {"BH", SIZE_BYTE, 0 },

    // ========================================================================
    // >> 16-bit General purpose registers
    // ========================================================================
    {"AX", SIZE_WORD, 0 },
    {"CX", SIZE_WORD, 0 },
    {"DX", SIZE_WORD, 0 },
    {"BX", SIZE_WORD, 0 },
    {"SP", SIZE_WORD, 0 },
    {"BP", SIZE_WORD, 0 },
    {"SI", SIZE_WORD, 0 },
    {"DI", SIZE_WORD, 0 },

#if DYNO_ARCH_X86 == 64
    {"R8W", SIZE_WORD, 0 },
    {"R9W", SIZE_WORD, 0 },
    {"R10W", SIZE_WORD, 0 },
    {"R11W", SIZE_WORD, 0 },
    {"R12W", SIZE_WORD, 0 },
    {"R13W", SIZE_WORD, 0 },
    {"R14W", SIZE_WORD, 0 },
    {"R15W", SIZE_WORD, 0 },
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 32-bit General purpose registers
    // ========================================================================
    {"EAX", SIZE_DWORD, 0 },
    {"ECX", SIZE_DWORD, 0 },
    {"EDX", SIZE_DWORD, 0 },
    {"EBX", SIZE_DWORD, 0 },
    {"ESP", SIZE_DWORD, 0 },
    {"EBP", SIZE_DWORD, 0 },
    {"ESI", SIZE_DWORD, 0 },
    {"EDI", SIZE_DWORD, 0 },

#if DYNO_ARCH_X86 == 64
    {"R8D", SIZE_DWORD, 0 },
    {"R9D", SIZE_DWORD, 0 },
    {"R10D", SIZE_DWORD, 0 },
    {"R11D", SIZE_DWORD, 0 },
    {"R12D", SIZE_DWORD, 0 },
    {"R13D", SIZE_DWORD, 0 },
    {"R14D", SIZE_DWORD, 0 },
    {"R15D", SIZE_DWORD, 0 },
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 64-bit General purpose registers
    // ========================================================================
#if DYNO_ARCH_X86 == 64
    {"RAX", SIZE_QWORD, 0 },
    {"RCX", SIZE_QWORD, 0 },
    {"RDX", SIZE_QWORD, 0 },
    {"RBX", SIZE_QWORD, 0 },
    {"RSP", SIZE_QWORD, 0 },
    {"RBP", SIZE_QWORD, 0 },
    {"RSI", SIZE_QWORD, 0 },
    {"RDI", SIZE_QWORD, 0 },

    {"R8", SIZE_QWORD, 0 },
    {"R9", SIZE_QWORD, 0 },
    {"R10", SIZE_QWORD, 0 },
    {"R11", SIZE_QWORD, 0 },
    {"R12", SIZE_QWORD, 0 },
    {"R13", SIZE_QWORD, 0 },
    {"R14", SIZE_QWORD, 0 },
    {"R15", SIZE_QWORD, 0 },
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 64-bit MM (MMX) registers
    // ========================================================================
    {"MM0", SIZE_QWORD, 0 },
    {"MM1", SIZE_QWORD, 0 },
    {"MM2", SIZE_QWORD, 0 },
    {"MM3", SIZE_QWORD, 0 },
    {"MM4", SIZE_QWORD, 0 },
    {"MM5", SIZE_QWORD, 0 },
    {"MM6", SIZE_QWORD, 0 },
    {"MM7", SIZE_QWORD, 0 },

    // ========================================================================
    // >> 128-bit XMM registers
    // ========================================================================
    {"XMM0", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM1", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM2", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM3", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM4", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM5", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM6", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM7", SIZE_XMMWORD, SIZE_XMMWORD },
#if DYNO_ARCH_X86 == 64
    {"XMM8", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM9", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM10", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM11", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM12", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM13", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM14", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM15", SIZE_XMMWORD, SIZE_XMMWORD },
#ifdef DYNO_PLATFORM_AVX512
    {"XMM16", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM17", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM18", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM19", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM20", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM21", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM22", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM23", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM24", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM25", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM26", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM27", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM28", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM29", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM30", SIZE_XMMWORD, SIZE_XMMWORD },
    {"XMM31", SIZE_XMMWORD, SIZE_XMMWORD },
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 256-bit YMM registers
    // ========================================================================
#if DYNO_ARCH_X86 == 64
    {"YMM0", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM1", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM2", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM3", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM4", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM5", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM6", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM7", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM8", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM9", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM10", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM11", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM12", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM13", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM14", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM15", SIZE_YMMWORD, SIZE_YMMWORD },
#ifdef DYNO_PLATFORM_AVX512
    {"YMM16", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM17", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM18", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM19", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM20", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM21", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM22", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM23", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM24", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM25", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM26", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM27", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM28", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM29", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM30", SIZE_YMMWORD, SIZE_YMMWORD },
    {"YMM31", SIZE_YMMWORD, SIZE_YMMWORD },
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 512-bit ZMM registers
    // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
    {"ZMM0", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM1", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM2", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM3", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM4", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM5", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM6", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM7", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM8", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM9", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM10", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM11", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM12", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM13", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM14", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM15", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM16", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM17", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM18", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM19", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM20", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM21", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM22", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM23", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM24", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM25", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM26", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM27", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM28", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM29", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM30", SIZE_ZMMWORD, SIZE_ZMMWORD },
    {"ZMM31", SIZE_ZMMWORD, SIZE_ZMMWORD },
#endif // DYNO_PLATFORM_AVX512

    // ========================================================================
    // >> 16-bit Segment registers
    // ========================================================================
    {"CS", SIZE_WORD, 0 },
    {"SS", SIZE_WORD, 0 },
    {"DS", SIZE_WORD, 0 },
    {"ES", SIZE_WORD, 0 },
    {"FS", SIZE_WORD, 0 },
    {"GS", SIZE_WORD, 0 },

    // ========================================================================
    // >> 80-bit FPU registers
    // ========================================================================
#if DYNO_ARCH_X86 == 32
    {"ST0", SIZE_TWORD, 0 },
    {"ST1", SIZE_TWORD, 0 },
    {"ST3", SIZE_TWORD, 0 },
    {"ST4", SIZE_TWORD, 0 },
    {"ST5", SIZE_TWORD, 0 },
    {"ST6", SIZE_TWORD, 0 },
    {"ST7", SIZE_TWORD, 0 },
#endif // DYNO_ARCH_X86
}};

Registers::Registers(const std::vector<RegisterType>& registers) {
    m_registers.reserve(registers.size());

    for (RegisterType type : registers) {
        const auto& [name, size, alignment] = s_RegisterTable.at(type);
        m_registers.emplace_back(type, size, alignment);
    }
}

const Register& Registers::operator[](RegisterType regType) const {
    return at(regType);
}

const Register& Registers::at(RegisterType regType, bool reverse) const {
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

const RegisterInfo& RegisterTypeInfo(RegisterType regType){
    return s_RegisterTable.at(regType);
}

size_t dyno::RegisterTypeToSSEIndex(RegisterType regType) {
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

RegisterType dyno::SSEIndexToRegisterType(size_t index, size_t size) {
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

/*std::ostream& operator<<(std::ostream& os, dyno::RegisterType v) {
    os << RegisterTypeToName(v);
    return os;
}*/
