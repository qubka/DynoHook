#include "registers.h"

using namespace dyno;

Register Registers::s_None(NONE, (RegisterSize)0);
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
    XMM6,
    XMM7,
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

struct RegisterData {
    const char* name;
    RegisterSize size;
    uint8_t alignment;
    uint8_t index;
};

#define INVALID UINT8_MAX

std::vector<RegisterData> s_RegisterTable = {
    // ========================================================================
    // >> 8-bit General purpose registers
    // ========================================================================
    {"AL", SIZE_BYTE, 0, INVALID },
    {"CL", SIZE_BYTE, 0, INVALID },
    {"DL", SIZE_BYTE, 0, INVALID },
    {"BL", SIZE_BYTE, 0, INVALID },

#if DYNO_ARCH_X86 == 64
    {"SPL", SIZE_BYTE, 0, INVALID },
    {"BPL", SIZE_BYTE, 0, INVALID },
    {"SIL", SIZE_BYTE, 0, INVALID },
    {"DIL", SIZE_BYTE, 0, INVALID },
    {"R8B", SIZE_BYTE, 0, INVALID },
    {"R9B", SIZE_BYTE, 0, INVALID },
    {"R10B", SIZE_BYTE, 0, INVALID },
    {"R11B", SIZE_BYTE, 0, INVALID },
    {"R12B", SIZE_BYTE, 0, INVALID },
    {"R13B", SIZE_BYTE, 0, INVALID },
    {"R14B", SIZE_BYTE, 0, INVALID },
    {"R15B", SIZE_BYTE, 0, INVALID },
#endif // DYNO_ARCH_X86

    {"AH", SIZE_BYTE, 0, INVALID },
    {"CH", SIZE_BYTE, 0, INVALID },
    {"DH", SIZE_BYTE, 0, INVALID },
    {"BH", SIZE_BYTE, 0, INVALID },

    // ========================================================================
    // >> 16-bit General purpose registers
    // ========================================================================
    {"AX", SIZE_WORD, 0, INVALID },
    {"CX", SIZE_WORD, 0, INVALID },
    {"DX", SIZE_WORD, 0, INVALID },
    {"BX", SIZE_WORD, 0, INVALID },
    {"SP", SIZE_WORD, 0, INVALID },
    {"BP", SIZE_WORD, 0, INVALID },
    {"SI", SIZE_WORD, 0, INVALID },
    {"DI", SIZE_WORD, 0, INVALID },

#if DYNO_ARCH_X86 == 64
    {"R8W", SIZE_WORD, 0, INVALID },
    {"R9W", SIZE_WORD, 0, INVALID },
    {"R10W", SIZE_WORD, 0, INVALID },
    {"R11W", SIZE_WORD, 0, INVALID },
    {"R12W", SIZE_WORD, 0, INVALID },
    {"R13W", SIZE_WORD, 0, INVALID },
    {"R14W", SIZE_WORD, 0, INVALID },
    {"R15W", SIZE_WORD, 0, INVALID },
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 32-bit General purpose registers
    // ========================================================================
    {"EAX", SIZE_DWORD, 0, INVALID },
    {"ECX", SIZE_DWORD, 0, INVALID },
    {"EDX", SIZE_DWORD, 0, INVALID },
    {"EBX", SIZE_DWORD, 0, INVALID },
    {"ESP", SIZE_DWORD, 0, INVALID },
    {"EBP", SIZE_DWORD, 0, INVALID },
    {"ESI", SIZE_DWORD, 0, INVALID },
    {"EDI", SIZE_DWORD, 0, INVALID },

#if DYNO_ARCH_X86 == 64
    {"R8D", SIZE_DWORD, 0, INVALID },
    {"R9D", SIZE_DWORD, 0, INVALID },
    {"R10D", SIZE_DWORD, 0, INVALID },
    {"R11D", SIZE_DWORD, 0, INVALID },
    {"R12D", SIZE_DWORD, 0, INVALID },
    {"R13D", SIZE_DWORD, 0, INVALID },
    {"R14D", SIZE_DWORD, 0, INVALID },
    {"R15D", SIZE_DWORD, 0, INVALID },
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 64-bit General purpose registers
    // ========================================================================
#if DYNO_ARCH_X86 == 64
    {"RAX", SIZE_QWORD, 0, INVALID },
    {"RCX", SIZE_QWORD, 0, INVALID },
    {"RDX", SIZE_QWORD, 0, INVALID },
    {"RBX", SIZE_QWORD, 0, INVALID },
    {"RSP", SIZE_QWORD, SIZE_XMMWORD, INVALID },
    {"RBP", SIZE_QWORD, 0, INVALID },
    {"RSI", SIZE_QWORD, 0, INVALID },
    {"RDI", SIZE_QWORD, 0, INVALID },

    {"R8", SIZE_QWORD, 0, INVALID },
    {"R9", SIZE_QWORD, 0, INVALID },
    {"R10", SIZE_QWORD, 0, INVALID },
    {"R11", SIZE_QWORD, 0, INVALID },
    {"R12", SIZE_QWORD, 0, INVALID },
    {"R13", SIZE_QWORD, 0, INVALID },
    {"R14", SIZE_QWORD, 0, INVALID },
    {"R15", SIZE_QWORD, 0, INVALID },
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 64-bit MM (MMX) registers
    // ========================================================================
    {"MM0", SIZE_QWORD, 0, 0 },
    {"MM1", SIZE_QWORD, 0, 1 },
    {"MM2", SIZE_QWORD, 0, 2 },
    {"MM3", SIZE_QWORD, 0, 3 },
    {"MM4", SIZE_QWORD, 0, 4 },
    {"MM5", SIZE_QWORD, 0, 5 },
    {"MM6", SIZE_QWORD, 0, 6 },
    {"MM7", SIZE_QWORD, 0, 7 },

    // ========================================================================
    // >> 128-bit XMM registers
    // ========================================================================
    {"XMM0", SIZE_XMMWORD, SIZE_XMMWORD, 0 },
    {"XMM1", SIZE_XMMWORD, SIZE_XMMWORD, 1 },
    {"XMM2", SIZE_XMMWORD, SIZE_XMMWORD, 2 },
    {"XMM3", SIZE_XMMWORD, SIZE_XMMWORD, 3 },
    {"XMM4", SIZE_XMMWORD, SIZE_XMMWORD, 4 },
    {"XMM5", SIZE_XMMWORD, SIZE_XMMWORD, 5 },
    {"XMM6", SIZE_XMMWORD, SIZE_XMMWORD, 6 },
    {"XMM7", SIZE_XMMWORD, SIZE_XMMWORD, 7 },
#if DYNO_ARCH_X86 == 64
    {"XMM8", SIZE_XMMWORD, SIZE_XMMWORD, 8 },
    {"XMM9", SIZE_XMMWORD, SIZE_XMMWORD, 9 },
    {"XMM10", SIZE_XMMWORD, SIZE_XMMWORD, 10 },
    {"XMM11", SIZE_XMMWORD, SIZE_XMMWORD, 11 },
    {"XMM12", SIZE_XMMWORD, SIZE_XMMWORD, 12 },
    {"XMM13", SIZE_XMMWORD, SIZE_XMMWORD, 13 },
    {"XMM14", SIZE_XMMWORD, SIZE_XMMWORD, 14 },
    {"XMM15", SIZE_XMMWORD, SIZE_XMMWORD, 15 },
#ifdef DYNO_PLATFORM_AVX512
    {"XMM16", SIZE_XMMWORD, SIZE_XMMWORD, 16 },
    {"XMM17", SIZE_XMMWORD, SIZE_XMMWORD, 17 },
    {"XMM18", SIZE_XMMWORD, SIZE_XMMWORD, 18 },
    {"XMM19", SIZE_XMMWORD, SIZE_XMMWORD, 19 },
    {"XMM20", SIZE_XMMWORD, SIZE_XMMWORD, 20 },
    {"XMM21", SIZE_XMMWORD, SIZE_XMMWORD, 21 },
    {"XMM22", SIZE_XMMWORD, SIZE_XMMWORD, 22 },
    {"XMM23", SIZE_XMMWORD, SIZE_XMMWORD, 23 },
    {"XMM24", SIZE_XMMWORD, SIZE_XMMWORD, 24 },
    {"XMM25", SIZE_XMMWORD, SIZE_XMMWORD, 25 },
    {"XMM26", SIZE_XMMWORD, SIZE_XMMWORD, 26 },
    {"XMM27", SIZE_XMMWORD, SIZE_XMMWORD, 27 },
    {"XMM28", SIZE_XMMWORD, SIZE_XMMWORD, 28 },
    {"XMM29", SIZE_XMMWORD, SIZE_XMMWORD, 29 },
    {"XMM30", SIZE_XMMWORD, SIZE_XMMWORD, 30 },
    {"XMM31", SIZE_XMMWORD, SIZE_XMMWORD, 31 },
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 256-bit YMM registers
    // ========================================================================
#if DYNO_ARCH_X86 == 64
    {"YMM0", SIZE_YMMWORD, SIZE_YMMWORD, 0 },
    {"YMM1", SIZE_YMMWORD, SIZE_YMMWORD, 1 },
    {"YMM2", SIZE_YMMWORD, SIZE_YMMWORD, 2 },
    {"YMM3", SIZE_YMMWORD, SIZE_YMMWORD, 3 },
    {"YMM4", SIZE_YMMWORD, SIZE_YMMWORD, 4 },
    {"YMM5", SIZE_YMMWORD, SIZE_YMMWORD, 5 },
    {"YMM6", SIZE_YMMWORD, SIZE_YMMWORD, 6 },
    {"YMM7", SIZE_YMMWORD, SIZE_YMMWORD, 7 },
    {"YMM8", SIZE_YMMWORD, SIZE_YMMWORD, 8 },
    {"YMM9", SIZE_YMMWORD, SIZE_YMMWORD, 9 },
    {"YMM10", SIZE_YMMWORD, SIZE_YMMWORD, 10 },
    {"YMM11", SIZE_YMMWORD, SIZE_YMMWORD, 11 },
    {"YMM12", SIZE_YMMWORD, SIZE_YMMWORD, 12 },
    {"YMM13", SIZE_YMMWORD, SIZE_YMMWORD, 13 },
    {"YMM14", SIZE_YMMWORD, SIZE_YMMWORD, 14 },
    {"YMM15", SIZE_YMMWORD, SIZE_YMMWORD, 15 },
#ifdef DYNO_PLATFORM_AVX512
    {"YMM16", SIZE_YMMWORD, SIZE_YMMWORD, 16 },
    {"YMM17", SIZE_YMMWORD, SIZE_YMMWORD, 17 },
    {"YMM18", SIZE_YMMWORD, SIZE_YMMWORD, 18 },
    {"YMM19", SIZE_YMMWORD, SIZE_YMMWORD, 19 },
    {"YMM20", SIZE_YMMWORD, SIZE_YMMWORD, 20 },
    {"YMM21", SIZE_YMMWORD, SIZE_YMMWORD, 21 },
    {"YMM22", SIZE_YMMWORD, SIZE_YMMWORD, 22 },
    {"YMM23", SIZE_YMMWORD, SIZE_YMMWORD, 23 },
    {"YMM24", SIZE_YMMWORD, SIZE_YMMWORD, 24 },
    {"YMM25", SIZE_YMMWORD, SIZE_YMMWORD, 25 },
    {"YMM26", SIZE_YMMWORD, SIZE_YMMWORD, 26 },
    {"YMM27", SIZE_YMMWORD, SIZE_YMMWORD, 27 },
    {"YMM28", SIZE_YMMWORD, SIZE_YMMWORD, 28 },
    {"YMM29", SIZE_YMMWORD, SIZE_YMMWORD, 29 },
    {"YMM30", SIZE_YMMWORD, SIZE_YMMWORD, 30 },
    {"YMM31", SIZE_YMMWORD, SIZE_YMMWORD, 31 },
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_ARCH_X86

    // ========================================================================
    // >> 512-bit ZMM registers
    // ========================================================================
#ifdef DYNO_PLATFORM_AVX512
    {"ZMM0", SIZE_ZMMWORD, SIZE_ZMMWORD, 0 },
    {"ZMM1", SIZE_ZMMWORD, SIZE_ZMMWORD, 1 },
    {"ZMM2", SIZE_ZMMWORD, SIZE_ZMMWORD, 2 },
    {"ZMM3", SIZE_ZMMWORD, SIZE_ZMMWORD, 3 },
    {"ZMM4", SIZE_ZMMWORD, SIZE_ZMMWORD, 4 },
    {"ZMM5", SIZE_ZMMWORD, SIZE_ZMMWORD, 5 },
    {"ZMM6", SIZE_ZMMWORD, SIZE_ZMMWORD, 6 },
    {"ZMM7", SIZE_ZMMWORD, SIZE_ZMMWORD, 7 },
    {"ZMM8", SIZE_ZMMWORD, SIZE_ZMMWORD, 8 },
    {"ZMM9", SIZE_ZMMWORD, SIZE_ZMMWORD, 9 },
    {"ZMM10", SIZE_ZMMWORD, SIZE_ZMMWORD, 10 },
    {"ZMM11", SIZE_ZMMWORD, SIZE_ZMMWORD, 11 },
    {"ZMM12", SIZE_ZMMWORD, SIZE_ZMMWORD, 12 },
    {"ZMM13", SIZE_ZMMWORD, SIZE_ZMMWORD, 13 },
    {"ZMM14", SIZE_ZMMWORD, SIZE_ZMMWORD, 14 },
    {"ZMM15", SIZE_ZMMWORD, SIZE_ZMMWORD, 15 },
    {"ZMM16", SIZE_ZMMWORD, SIZE_ZMMWORD, 16 },
    {"ZMM17", SIZE_ZMMWORD, SIZE_ZMMWORD, 17 },
    {"ZMM18", SIZE_ZMMWORD, SIZE_ZMMWORD, 18 },
    {"ZMM19", SIZE_ZMMWORD, SIZE_ZMMWORD, 19 },
    {"ZMM20", SIZE_ZMMWORD, SIZE_ZMMWORD, 20 },
    {"ZMM21", SIZE_ZMMWORD, SIZE_ZMMWORD, 21 },
    {"ZMM22", SIZE_ZMMWORD, SIZE_ZMMWORD, 22 },
    {"ZMM23", SIZE_ZMMWORD, SIZE_ZMMWORD, 23 },
    {"ZMM24", SIZE_ZMMWORD, SIZE_ZMMWORD, 24 },
    {"ZMM25", SIZE_ZMMWORD, SIZE_ZMMWORD, 25 },
    {"ZMM26", SIZE_ZMMWORD, SIZE_ZMMWORD, 26 },
    {"ZMM27", SIZE_ZMMWORD, SIZE_ZMMWORD, 27 },
    {"ZMM28", SIZE_ZMMWORD, SIZE_ZMMWORD, 28 },
    {"ZMM29", SIZE_ZMMWORD, SIZE_ZMMWORD, 29 },
    {"ZMM30", SIZE_ZMMWORD, SIZE_ZMMWORD, 30 },
    {"ZMM31", SIZE_ZMMWORD, SIZE_ZMMWORD, 31 },
#endif // DYNO_PLATFORM_AVX512

    // ========================================================================
    // >> 16-bit Segment registers
    // ========================================================================
    {"CS", SIZE_WORD, 0, INVALID },
    {"SS", SIZE_WORD, 0, INVALID },
    {"DS", SIZE_WORD, 0, INVALID },
    {"ES", SIZE_WORD, 0, INVALID },
    {"FS", SIZE_WORD, 0, INVALID },
    {"GS", SIZE_WORD, 0, INVALID },

    // ========================================================================
    // >> 80-bit FPU registers
    // ========================================================================
#if DYNO_ARCH_X86 == 32
    {"ST0", SIZE_TWORD, 0, INVALID },
    {"ST1", SIZE_TWORD, 0, 1 },
    {"ST2", SIZE_TWORD, 0, 2 },
    {"ST3", SIZE_TWORD, 0, 3 },
    {"ST4", SIZE_TWORD, 0, 4 },
    {"ST5", SIZE_TWORD, 0, 5 },
    {"ST6", SIZE_TWORD, 0, 6 },
    {"ST7", SIZE_TWORD, 0, 7 },
#endif // DYNO_ARCH_X86
};

Registers::Registers(const std::vector<RegisterType>& registers) {
    m_registers.reserve(registers.size());

    for (RegisterType regType : registers) {
        const auto& [name, size, alignment, index] = s_RegisterTable[regType];
        m_registers.emplace_back(regType, size, alignment);
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

const char* dyno::RegisterTypeToName(RegisterType regType) {
    return s_RegisterTable.at(regType).name;
}

size_t dyno::RegisterTypeToSize(RegisterType regType) {
    return s_RegisterTable.at(regType).size;
}

size_t dyno::RegisterTypeToAlignment(RegisterType regType) {
    return s_RegisterTable.at(regType).alignment;
}

size_t dyno::RegisterTypeToIndex(RegisterType regType) {
    return s_RegisterTable.at(regType).index;
}

RegisterType dyno::IndexToRegisterType(size_t idx, size_t sz) {
    for (size_t i = 0; i < s_RegisterTable.size(); ++i) {
        const auto& [name, size, alignment, index] = s_RegisterTable[i];
        if (index == idx && size == sz) {
            return static_cast<RegisterType>(i);
        }
    }
    return NONE;
}

/*std::ostream& operator<<(std::ostream& os, dyno::RegisterType v) {
    os << RegisterTypeToName(v);
    return os;
}*/
