#include "memory.h"

#ifdef DYNO_PLATFORM_WINDOWS
#include <windows.h>
#elif DYNO_PLATFORM_LINUX
#include <sys/mman.h>
#include <unistd.h>
#include <fstream>
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

    /*std::ostream& operator<<(std::ostream& os, ProtFlag flags) {
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
    }*/

#ifdef DYNO_PLATFORM_WINDOWS

    bool MemoryProtect::protect(void* address, size_t size, ProtFlag flags) {
        DWORD oldProtect;
        bool success = VirtualProtect(address, size, TranslateProtection(flags), &oldProtect);
        m_oldProtection = TranslateProtection((int) oldProtect);
        return success;
    }

    void* Memory::AllocateMemory(void* address, size_t size) {
        return VirtualAlloc(address, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    void Memory::FreeMemory(void* address, size_t size) {
        VirtualFree(address, size, MEM_RELEASE);
    }

    size_t Memory::GetPageSize() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwPageSize;
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
        uintptr_t start;
        uintptr_t end;
        dyno::ProtFlag prot;
    };

    static region_t get_region_from_addr(uintptr_t address) {
        region_t res{};

        std::ifstream f("/proc/self/maps");
        std::string s;
        while (std::getline(f, s)) {
            if (!s.empty() && s.find("vdso") == std::string::npos && s.find("vsyscall") == std::string::npos) {
                char* strend = &s[0];
                uintptr_t start = strtoul(strend  , &strend, 16);
                uintptr_t end   = strtoul(strend+1, &strend, 16);
                if (start != 0 && end != 0 && start <= address && address < end) {
                    res.start = start;
                    res.end = end;

                    ++strend;
                    if (strend[0] == 'r')
                        res.prot = res.prot | ProtFlag::R;

                    if (strend[1] == 'w')
                        res.prot = res.prot | ProtFlag::W;

                    if (strend[2] == 'x')
                        res.prot = res.prot | ProtFlag::X;

                    if (res.prot == ProtFlag::UNSET)
                        res.prot = ProtFlag::N;

                    break;
                }
            }
        }
        return res;
    }

    bool MemoryProtect::protect(void* address, size_t size, ProtFlag flags) {
        const size_t pageSize = sysconf(_SC_PAGE_SIZE);
        uintptr_t pageAddr = (uintptr_t) address;
        pageAddr = pageAddr - (pageAddr % pageSize);
        m_oldProtection = get_region_from_addr(pageAddr).prot;
        return mprotect((void*) pageAddr, size, TranslateProtection(m_flags)) != -1;
    }

    void* Memory::AllocateMemory(void* address, size_t size) {
        return mmap(address, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    void Memory::FreeMemory(void* address, size_t size) {
        munmap(address, size);
    }

    size_t Memory::GetPageSize() {
        return sysconf(_SC_PAGE_SIZE);
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

        if (prot & PROT_EXEC)
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