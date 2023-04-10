#pragma once

namespace dyno {
    enum RegisterType : uint8_t {
        // No register at all.
        NONE,

        // ========================================================================
        // >> 8-bit General purpose registers
        // ========================================================================
        AL,
        CL,
        DL,
        BL,

#ifdef ENV64BIT
        SPL,
        BPL,
        SIL,
        DIL,
        R8B,
        R9B,
        R10B,
        R11B,
        R12B,
        R13B,
        R14B,
        R15B,
#endif // ENV64BIT

        AH,
        CH,
        DH,
        BH,

        // ========================================================================
        // >> 16-bit General purpose registers
        // ========================================================================
        AX,
        CX,
        DX,
        BX,
        SP,
        BP,
        SI,
        DI,

#ifdef ENV64BIT
        R8W,
        R9W,
        R10W,
        R11W,
        R12W,
        R13W,
        R14W,
        R15W,
#endif // ENV64BIT

        // ========================================================================
        // >> 32-bit General purpose registers
        // ========================================================================
        EAX,
        ECX,
        EDX,
        EBX,
        ESP,
        EBP,
        ESI,
        EDI,

#ifdef ENV64BIT
        R8D,
        R9D,
        R10D,
        R11D,
        R12D,
        R13D,
        R14D,
        R15D,
#endif // ENV64BIT

        // ========================================================================
        // >> 64-bit General purpose registers
        // ========================================================================
#ifdef ENV64BIT
        RAX,
        RCX,
        RDX,
        RBX,
        RSP,
        RBP,
        RSI,
        RDI,

        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
#endif // ENV64BIT

        // ========================================================================
        // >> 64-bit MM (MMX) registers
        // ========================================================================
        MM0,
        MM1,
        MM2,
        MM3,
        MM4,
        MM5,
        MM6,
        MM7,

        // ========================================================================
        // >> 128-bit XMM registers
        // ========================================================================
        XMM0,
        XMM1,
        XMM2,
        XMM3,
        XMM4,
        XMM5,
        XMM6,
        XMM7,
#ifdef ENV64BIT
        XMM8,
        XMM9,
        XMM10,
        XMM11,
        XMM12,
        XMM13,
        XMM14,
        XMM15,
#ifdef AVX512
        XMM16,
        XMM17,
        XMM18,
        XMM19,
        XMM20,
        XMM21,
        XMM22,
        XMM23,
        XMM24,
        XMM25,
        XMM26,
        XMM27,
        XMM28,
        XMM29,
        XMM30,
        XMM31,
#endif // AVX512
#endif // ENV64BIT

        // ========================================================================
        // >> 256-bit YMM registers
        // ========================================================================
#ifdef ENV64BIT
        YMM0,
        YMM1,
        YMM2,
        YMM3,
        YMM4,
        YMM5,
        YMM6,
        YMM7,
        YMM8,
        YMM9,
        YMM10,
        YMM11,
        YMM12,
        YMM13,
        YMM14,
        YMM15,
#ifdef AVX512
        YMM16,
        YMM17,
        YMM18,
        YMM19,
        YMM20,
        YMM21,
        YMM22,
        YMM23,
        YMM24,
        YMM25,
        YMM26,
        YMM27,
        YMM28,
        YMM29,
        YMM30,
        YMM31,
#endif // AVX512
#endif // ENV64BIT

        // ========================================================================
        // >> 512-bit ZMM registers
        // ========================================================================
#ifdef AVX512
        ZMM0,
        ZMM1,
        ZMM2,
        ZMM3,
        ZMM4,
        ZMM5,
        ZMM6,
        ZMM7,
        ZMM8,
        ZMM9,
        ZMM10,
        ZMM11,
        ZMM12,
        ZMM13,
        ZMM14,
        ZMM15,
        ZMM16,
        ZMM17,
        ZMM18,
        ZMM19,
        ZMM20,
        ZMM21,
        ZMM22,
        ZMM23,
        ZMM24,
        ZMM25,
        ZMM26,
        ZMM27,
        ZMM28,
        ZMM29,
        ZMM30,
        ZMM31,
#endif // AVX512

        // ========================================================================
        // >> 16-bit Segment registers
        // ========================================================================
        CS,
        SS,
        DS,
        ES,
        FS,
        GS,

        // ========================================================================
        // >> 80-bit FPU registers
        // ========================================================================
#ifdef ENV32BIT
        ST0,
        ST1,
        ST2,
        ST3,
        ST4,
        ST5,
        ST6,
        ST7,
#endif // ENV32BIT
    };

    size_t RegisterTypeToSize(RegisterType regType);
    size_t RegisterTypeToAlignment(RegisterType regType);

    size_t RegisterTypeToSSEIndex(RegisterType regType);
    RegisterType SSEIndexToRegisterType(size_t index, size_t size = 0);

    enum RegisterSize : uint8_t {
        SIZE_BYTE = 1,
        SIZE_WORD = 2,
        SIZE_DWORD = 4,
        SIZE_QWORD = 8,
        SIZE_TWORD = 10,
        SIZE_XMMWORD = 16,
        SIZE_YMMWORD = 32,
        SIZE_ZMMWORD = 64,
    };

    class Register {
    public:
        Register(RegisterType type, size_t size, size_t alignment = 0) : m_size(size), m_alignment(alignment), m_type{type} {
            if (size == 0)
                m_address = nullptr;
            else if (alignment > 0)
#ifdef _WIN32
                m_address = _aligned_malloc(size, alignment);
#else
                m_address = aligned_alloc(alignment, size);
#endif
            else
                m_address = malloc(size);
        }

        ~Register() {
            if (m_address) {
#ifdef _WIN32
                if (m_alignment > 0)
                    _aligned_free(m_address);
                else
                    free(m_address);
#else
                free(m_address);
#endif
            }
        }

        Register(const Register& other) {
            m_size = other.m_size;
            m_alignment = other.m_alignment;
            m_type = other.m_type;
            if (m_alignment > 0)
#ifdef _WIN32
                m_address = _aligned_malloc(m_size, m_alignment);
#else
                m_address = aligned_alloc(m_iAlignment, m_iSize);
#endif
            else
                m_address = malloc(m_size);
            memcpy(m_address, other.m_address, m_size);
        }

        Register(Register&& other) noexcept {
            m_address = other.m_address;
            m_size = other.m_size;
            m_alignment = other.m_alignment;
            m_type = other.m_type;
            other.m_address = nullptr;
        }

        void* operator*() const {
            return m_address;
        }

        operator RegisterType() const {
            return m_type;
        }

        template<class T>
        T getAddress() const {
            return (T) m_address;
        }

        template<class T>
        T getValue() const {
            return *(T*) m_address;
        }

        template<class T>
        T getPointerValue(size_t offset = 0) const {
            return *(T*) (getValue<uintptr_t>() + offset);
        }

        template<class T>
        void setValue(T value) {
            *(T*) m_address = value;
        }

        template<class T>
        void setPointerValue(T value, size_t offset = 0) {
            *(T*) (getValue<uintptr_t>() + offset) = value;
        }

    private:
        void* m_address;
        uint16_t m_size;
        RegisterType m_type;
        uint8_t m_alignment;
    };

    class Registers {
    public:
        Registers(const std::vector<RegisterType>& registers);

        const Register& operator[](RegisterType regType) const;

        const Register& at(RegisterType regType, bool reverse = false) const;

        auto begin() { return m_registers.begin(); }
        auto begin() const { return m_registers.cbegin(); }
        auto end() { return m_registers.end(); }
        auto end() const { return m_registers.cend(); }

    private:
        std::vector<Register> m_registers;
    };
}