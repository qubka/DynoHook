#include "memory.hpp"

#ifdef DYNO_PLATFORM_WINDOWS
#include <windows.h>
#elif DYNO_PLATFORM_LINUX
#include <sys/mman.h>
#include <unistd.h>
#include <climits>
#else
#error "Platform not supported!"
#endif

using namespace dyno;

MemoryProtect::MemoryProtect(void* addr, size_t size, ProtFlag flags) : m_address(addr), m_size(size), m_flags(flags), m_oldProtection(UNSET) {
    protect(m_address, m_size, m_flags);
}

MemoryProtect::~MemoryProtect() {
    protect(m_address, m_size, m_oldProtection);
}

namespace dyno {

    ProtFlag operator|(ProtFlag lhs, ProtFlag rhs) {
        using underlying = typename std::underlying_type<ProtFlag>::type;
        return static_cast<ProtFlag> (
            static_cast<underlying>(lhs) | static_cast<underlying>(rhs)
        );
    }

    bool operator&(ProtFlag lhs, ProtFlag rhs) {
        using underlying = typename std::underlying_type<ProtFlag>::type;
        return static_cast<underlying>(lhs) & static_cast<underlying>(rhs);
    }

    std::ostream& operator<<(std::ostream& os, ProtFlag flags) {
        if (flags == ProtFlag::UNSET) {
            os << "UNSET";
            return os;
        }

        if (flags & ProtFlag::X)
            os << "x";
        else
            os << "-";

        if (flags & ProtFlag::R)
            os << "r";
        else
            os << "-";

        if (flags & ProtFlag::W)
            os << "w";
        else
            os << "-";

        if (flags & ProtFlag::N)
            os << "n";
        else
            os << "-";

        if (flags & ProtFlag::P)
            os << " private";
        else if (flags & ProtFlag::S)
            os << " shared";
        return os;
    }

#ifdef DYNO_PLATFORM_WINDOWS

    bool MemoryProtect::protect(void* addr, size_t size, ProtFlag flags) {
        DWORD oldProtect;
        bool success = VirtualProtect(addr, size, TranslateProtection(flags), &oldProtect);
        m_oldProtection = TranslateProtection((int) oldProtect);
        return success;
    }

    void* AllocateMemory(void* addr, size_t size) {
        return VirtualAlloc(addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    void FreeMemory(void* addr, size_t size) {
        VirtualFree(addr, size, MEM_RELEASE);
    }

    void* AllocatePageNearAddress(void* targetAddr) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        const size_t pageSize = sysInfo.dwPageSize;
        uintptr_t minAddr = (uintptr_t) sysInfo.lpMinimumApplicationAddress;
        uintptr_t maxAddr = (uintptr_t) sysInfo.lpMaximumApplicationAddress;

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
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        const size_t pageSize = sysInfo.dwPageSize;
        FreeMemory(pageAddr, pageSize);
    }

    int TranslateProtection(ProtFlag flags) {
        int nativeFlag = 0;
        if (flags == ProtFlag::X)
            nativeFlag = PAGE_EXECUTE;

        if (flags == ProtFlag::R)
            nativeFlag = PAGE_READONLY;

        if (flags == ProtFlag::W || (flags == (ProtFlag::R | ProtFlag::W)))
            nativeFlag = PAGE_READWRITE;

        if ((flags & ProtFlag::X) && (flags & ProtFlag::R))
            nativeFlag = PAGE_EXECUTE_READ;

        if ((flags & ProtFlag::X) && (flags & ProtFlag::W))
            nativeFlag = PAGE_EXECUTE_READWRITE;

        if (flags & ProtFlag::N)
            nativeFlag = PAGE_NOACCESS;
        return nativeFlag;
    }

    ProtFlag TranslateProtection(int prot) {
        ProtFlag flags = ProtFlag::UNSET;
        switch (prot) {
        case PAGE_EXECUTE:
            flags = flags | ProtFlag::X;
            break;
        case PAGE_READONLY:
            flags = flags | ProtFlag::R;
            break;
        case PAGE_READWRITE:
            flags = flags | ProtFlag::W;
            flags = flags | ProtFlag::R;
            break;
        case PAGE_EXECUTE_READWRITE:
            flags = flags | ProtFlag::X;
            flags = flags | ProtFlag::R;
            flags = flags | ProtFlag::W;
            break;
        case PAGE_EXECUTE_READ:
            flags = flags | ProtFlag::X;
            flags = flags | ProtFlag::R;
            break;
        case PAGE_NOACCESS:
            flags = flags | ProtFlag::N;
            break;
        }
        return flags;
    }

#elif DYNO_PLATFORM_LINUX

    struct region_t {
        uint64_t start;
        uint64_t end;
        dyno::ProtFlag prot;
    };

    static region_t get_region_from_addr(uint64_t addr) {
        region_t res{};

        std::ifstream f("/proc/self/maps");
        std::string s;
        while (std::getline(f, s)) {
            if (!s.empty() && s.find("vdso") == std::string::npos && s.find("vsyscall") == std::string::npos) {
                char* strend = &s[0];
                uint64_t start = strtoul(strend  , &strend, 16);
                uint64_t end   = strtoul(strend+1, &strend, 16);
                if (start != 0 && end != 0 && start <= addr && addr < end) {
                    res.start = start;
                    res.end = end;

                    ++strend;
                    if (strend[0] == 'r')
                        res.prot = res.prot | ProtFlag::R;

                    if (strend[1] == 'w')
                        res.prot = res.prot | ProtFlag::W;

                    if (strend[2] == 'x')
                        res.prot = res.prot | ProtFlag::X;

                    if(res.prot == ProtFlag::UNSET)
                        res.prot = ProtFlag::N;

                    break;
                }
            }
        }
        return res;
    }

    bool MemoryProtect::protect(void* addr, size_t size, ProtFlag flags) {
        const size_t pageSize = sysconf(_SC_PAGE_SIZE);
        uintptr_t pageAddr = (uintptr_t) addr;
        pageAddr = pageAddr - (pageAddr % pageSize);
        m_oldProtection = get_region_from_addr(pageAddr).prot;
        return mprotect((void*) pageAddr, size, TranslateProtection(m_flags)) != -1;
    }

    void* AllocateMemory(void* addr, size_t size) {
        return mmap(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    void FreeMemory(void* addr, size_t size) {
        munmap(addr, size);
    }

    void* AllocatePageNearAddress(void* targetAddr) {
        const size_t pageSize = sysconf(_SC_PAGE_SIZE);
        uintptr_t minAddr = (uintptr_t) pageSize;
        uintptr_t maxAddr = uintptr_t(-1) - pageSize;

        uintptr_t startAddr = (uintptr_t(targetAddr) & ~(pageSize - 1)); //round down to nearest page boundary

        minAddr = std::min(startAddr - 0x7FFFFF00, minAddr);
        maxAddr = std::max(startAddr + 0x7FFFFF00, maxAddr);

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
        const size_t pageSize = sysconf(_SC_PAGE_SIZE);
        FreeMemory(pageAddr, pageSize);
    }

    int TranslateProtection(ProtFlag flags) {
        int nativeFlag = PROT_NONE;
        if (flags & ProtFlag::X)
            nativeFlag |= PROT_EXEC;

        if (flags & ProtFlag::R)
            nativeFlag |= PROT_READ;

        if (flags & ProtFlag::W)
            nativeFlag |= PROT_WRITE;

        if (flags & ProtFlag::N)
            nativeFlag = PROT_NONE;

        return nativeFlag;
    }

    ProtFlag TranslateProtection(int prot) {
        ProtFlag flags = ProtFlag::UNSET;

        if(prot & PROT_EXEC)
            flags = flags | ProtFlag::X;

        if (prot & PROT_READ)
            flags = flags | ProtFlag::R;

        if (prot & PROT_WRITE)
            flags = flags | ProtFlag::W;

        if (prot == PROT_NONE)
            flags = flags | ProtFlag::N;

        return flags;
    }

#elif DYNO_PLATFORM_APPLE

    int TranslateProtection(ProtFlag flags) {
        int nativeFlag = VM_PROT_NONE;
        if (flags & ProtFlag::X)
            nativeFlag |= PROT_EXEC;

        if (flags & ProtFlag::R)
            nativeFlag |= PROT_READ;

        if (flags & ProtFlag::W)
            nativeFlag |= PROT_WRITE;

        if (flags & ProtFlag::N)
            nativeFlag = PROT_NONE;

        return nativeFlag;
    }

    ProtFlag TranslateProtection(int prot) {
        ProtFlag flags = ProtFlag::UNSET;

        if (prot & VM_PROT_EXECUTE)
            flags = flags | ProtFlag::X;

        if (prot & VM_PROT_READ)
            flags = flags | ProtFlag::R;

        if (prot & VM_PROT_WRITE)
            flags = flags | ProtFlag::W;

        if (prot == VM_PROT_NONE)
            flags = flags | ProtFlag::N;

        return flags;
    }

#endif

}