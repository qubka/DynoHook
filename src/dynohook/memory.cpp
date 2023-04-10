#include "memory.hpp"

using namespace dyno;

MemoryProtect::MemoryProtect(void* addr, size_t size, unsigned long flags) : m_address{addr}, m_size{size}, m_flags{flags}, m_oldProtection{0} {
    protect(m_address, m_size, m_flags);
}

MemoryProtect::~MemoryProtect() {
    protect(m_address, m_size, m_oldProtection);
}

bool MemoryProtect::protect(void* addr, size_t size, unsigned long flags) {
#ifdef _WIN32
    return VirtualProtect(m_address, m_size, m_flags, &m_oldProtection);
#else
    m_oldProtection = PROT_READ | PROT_EXEC; // TODO: Find default value
    const size_t pageSize = sysconf(_SC_PAGE_SIZE);
    uintptr_t pageAddr = (uintptr_t) addr;
    pageAddr = pageAddr - (pageAddr % pageSize);
    return mprotect((void*) pageAddr, size, (int) flags) != -1;
#endif
}

namespace dyno {
    void* AllocateMemory(void* addr, size_t size) {
#ifdef _WIN32
        return VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
        return mmap(addr, size, PAGE_EXECUTE_READWRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    }

    void FreeMemory(void* addr, size_t size) {
#ifdef _WIN32
        VirtualFree(addr, size, MEM_RELEASE);
#else
        munmap(addr, size);
#endif
    }

    void* AllocatePageNearAddress(void* targetAddr) {
#if _WIN32
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        const size_t pageSize = sysInfo.dwPageSize;
        uintptr_t minAddr = (uintptr_t) sysInfo.lpMinimumApplicationAddress;
        uintptr_t maxAddr = (uintptr_t) sysInfo.lpMaximumApplicationAddress;
#else
        const size_t pageSize = sysconf(_SC_PAGE_SIZE);
        uintptr_t minAddr = (uintptr_t) pageSize;
        uintptr_t maxAddr = (uint64_t) (128ull * 1024 * 1024 * 1024 * 1024);
        using namespace std;
#endif

        uintptr_t startAddr = (uintptr_t(targetAddr) & ~(pageSize - 1)); //round down to nearest page boundary

        minAddr = min(startAddr - 0x7FFFFF00, minAddr);
        maxAddr = max(startAddr + 0x7FFFFF00, maxAddr);

        uintptr_t startPage = (startAddr - (startAddr % pageSize));
        uintptr_t pageOffset = 1;

        while (true) {
            uintptr_t byteOffset = pageOffset * pageSize;
            uintptr_t highAddr = startPage + byteOffset;
            uintptr_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

            bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

            if (highAddr < maxAddr) {
                void* outAddr = AllocateMemory((void*) highAddr, pageSize);
                if (outAddr != nullptr && outAddr != (void*) -1)
                    return outAddr;
            }

            if (lowAddr > minAddr) {
                void* outAddr = AllocateMemory((void*) lowAddr, pageSize);
                if (outAddr != nullptr && outAddr != (void*) -1)
                    return outAddr;
            }

            pageOffset++;

            if (needsExit)
                break;
        }

        return nullptr;
    }

    void FreePage(void* pageAddr) {
#if _WIN32
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        const size_t pageSize = sysInfo.dwPageSize;
#else
        const size_t pageSize = sysconf(_SC_PAGE_SIZE);
#endif
        FreeMemory(pageAddr, pageSize);
    }
}