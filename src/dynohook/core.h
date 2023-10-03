#pragma once

#include <iostream>

#define LOG_PRINT(x) std::cout << (x) << std::endl;

#define NONCOPYABLE(x) x(const x&) = delete; \
                       x(x&&) = delete; \
                       x& operator=(const x&) = delete; \
                       x& operator=(x&&) = delete;

#define ITERATABLE(t, o) std::vector<t>::iterator begin() { return o.begin(); } \
                         std::vector<t>::iterator end() { return o.end(); } \
                         std::vector<t>::reverse_iterator rbegin() { return o.rbegin(); } \
                         std::vector<t>::reverse_iterator rend() { return o.rend(); } \
                         std::vector<t>::const_iterator begin() const { return o.begin(); } \
                         std::vector<t>::const_iterator end() const { return o.end(); } \
                         std::vector<t>::const_reverse_iterator rbegin() const { return o.rbegin(); } \
                         std::vector<t>::const_reverse_iterator rend() const { return o.rend(); }     \

namespace dyno {
    template< typename T >
    std::string int_to_hex(T i) {
        std::stringstream stream;
        stream << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex
               << (uintptr_t) i; // We cast to the highest possible int because uint8_t will be printed as char

        return stream.str();
    }

    //http://stackoverflow.com/questions/4840410/how-to-align-a-pointer-in-c
    static inline uintptr_t AlignUpwards(uintptr_t stack, size_t align) {
        assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
        assert(stack != 0);

        auto addr = stack;
        if (addr % align != 0)
            addr += align - (addr % align);
        assert(addr >= stack);
        return addr;
    }

    static inline uintptr_t AlignDownwards(uintptr_t stack, size_t align) {
        assert(align > 0 && (align & (align - 1)) == 0); /* Power of 2 */
        assert(stack != 0);

        auto addr = stack;
        addr -= addr % align;
        assert(addr <= stack);
        return addr;
    }

    //Credit to Dogmatt on unknowncheats.me for IsValidPtr
    // and https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
    #if DYNO_PLATFORM_WINDOWS
    #define _PTR_MAX_VALUE ((void*)0x000F000000000000)
    #else
    #define _PTR_MAX_VALUE ((void*)0xFFF00000)
    #endif // DYNO_PLATFORM_WINDOWS

    inline bool isValidPtr(void* p) { return (p >= (void*)0x10000) && (p < _PTR_MAX_VALUE) && p != nullptr; }

    inline bool isMatch(const char* addr, const char* pat, const char* msk) {
        size_t n = 0;
        while (addr[n] == pat[n] || msk[n] == (uint8_t)'?') {
            if (!msk[++n]) {
                return true;
            }
        }
        return false;
    }

#define INRANGE(x,a,b)	(x >= a && x <= b)
#define getBits(x)		(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte(x)		(getBits(x[0]) << 4 | getBits(x[1]))

    constexpr uint8_t FINDPATTERN_SCRATCH_SIZE = 64;

    // https://github.com/learn-more/findpattern-bench/blob/master/patterns/learn_more.h
    // must use space between bytes and ?? for wildcards. Do not add 0x prefix
    uintptr_t findPattern(uintptr_t rangeStart, size_t len, const char* pattern);
    uintptr_t findPattern_rev(uintptr_t rangeStart, size_t len, const char* pattern);
    uintptr_t getPatternSize(const char* pattern);

    bool boundedAllocSupported();
    uintptr_t boundAlloc(uintptr_t min, uintptr_t max, size_t size);
    uintptr_t boundAllocLegacy(uintptr_t min, uintptr_t max, size_t size);
    void     boundAllocFree(uintptr_t address, size_t size);
    size_t getAllocationAlignment();
    size_t getPageSize();

#if DYNO_ARCH_X86 == 64
    uint64_t calc_2gb_below(uint64_t address);
    uint64_t calc_2gb_above(uint64_t address);
#endif // DYNO_ARCH_X86

    inline std::string repeat_n(std::string_view s, size_t n, std::string_view delim = "") {
        std::string out;
        for (size_t i = 0; i < n; i++) {
            out += s;
            if (i != n - 1) {
                out += delim;
            }
        }
        return out;
    }
}