#pragma once

namespace dyno {

    class Memory {
    public:
        static void* AllocateMemory(void* address, size_t size);
        static void FreeMemory(void* address, size_t size);
        static size_t GetPageSize();
    };

    //unsafe enum by design to allow binary OR
    enum ProtFlag : uint8_t {
        UNSET = 0, // Value means this give no information about protection state (un-read)
        X = 1 << 1,
        R = 1 << 2,
        W = 1 << 3,
        S = 1 << 4,
        P = 1 << 5,
        N = 1 << 6, // Value equaling the linux flag PROT_UNSET (read the prot, and the prot is unset)
        RWX = R | W | X
    };

    int	TranslateProtection(ProtFlag flags);
    ProtFlag TranslateProtection(int prot);

    class MemoryProtect {
    public:
        MemoryProtect(void* addr, size_t size, ProtFlag flags);
        ~MemoryProtect();
        NONCOPYABLE(MemoryProtect);

    private:
        bool protect(void* addr, size_t size, ProtFlag flags);

        void* m_address;
        size_t m_size;
        ProtFlag m_flags;
        ProtFlag m_oldProtection;
    };
}

dyno::ProtFlag operator|(dyno::ProtFlag lhs, dyno::ProtFlag rhs);
bool operator&(dyno::ProtFlag lhs, dyno::ProtFlag rhs);
std::ostream& operator<<(std::ostream& os, dyno::ProtFlag v);