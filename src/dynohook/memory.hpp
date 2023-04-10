#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <climits>
#define PAGE_EXECUTE_READWRITE (PROT_READ | PROT_WRITE | PROT_EXEC)
#endif

namespace dyno {
    void* AllocateMemory(void* addr, size_t size);

    void FreeMemory(void* addr, size_t size);

    void* AllocatePageNearAddress(void* targetAddr);

    void FreePage(void* pageAddr);

    class MemoryProtect {
    public:
        MemoryProtect(void* addr, size_t size, unsigned long flags);
        ~MemoryProtect();

        bool protect(void* addr, size_t size, unsigned long flags);

    private:
        void* m_address;
        size_t m_size;
        unsigned long m_flags;
        unsigned long m_oldProtection;
    };
}