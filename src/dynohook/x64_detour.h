#pragma once

#include "adetour.h"
#include "range_allocator.h"

#include <asmjit/asmjit.h>

namespace dyno {
    class x64Detour : public ADetour {
    public:
        enum detour_scheme_t : uint8_t {
            VALLOC2 = 1 << 0, // use virtualalloc2 to allocate in range. Only on win10 > 1803
            INPLACE = 1 << 1, // use push-ret for fnCallback in-place storage.
            CODE_CAVE = 1 << 2, //searching for code-cave to keep fnCallback.
            INPLACE_SHORT = 1 << 3, // spoils rax register
            RECOMMENDED = VALLOC2 | INPLACE | CODE_CAVE,
            // first try to allocate, then fallback to code cave if not supported.
            // will not fallback on failure of allocation
            ALL = RECOMMENDED | INPLACE_SHORT,
        };

        x64Detour(uint64_t fnAddress, uint64_t fnCallback, uint64_t* userTrampVar);
        ~x64Detour() override;

        bool hook() override;
        bool unhook() override;

        Mode getArchType() const override;

        static uint8_t getMinJmpSize();

        detour_scheme_t getDetourScheme() const;

        void setDetourScheme(detour_scheme_t scheme);

        static const char* printDetourScheme(detour_scheme_t scheme);

    protected:
        RangeAllocator m_allocator;
        std::optional<uint64_t> m_valloc2_region;
        asmjit::JitRuntime m_asmjit_rt;

        detour_scheme_t m_chosenScheme{ detour_scheme_t::VALLOC2 };
        detour_scheme_t m_detourScheme{ detour_scheme_t::RECOMMENDED }; // this is the most stable configuration.

        bool makeTrampoline(insts_t& prologue, insts_t& outJmpTable);

        // assumes we are looking within a +-2GB window
        template<uint16_t SIZE>
        std::optional<uint64_t> findNearestCodeCave(uint64_t address);

        Instruction makeRelJmpWithAbsDest(uint64_t address, uint64_t abs_destination);
        std::optional<uint64_t> generateTranslationRoutine(const Instruction& instruction, uint64_t resume_address);

        bool make_inplace_trampoline(uint64_t base_address, const std::function<void(asmjit::x86::Assembler&)>& builder);

        bool allocate_jump_to_callback();
    };
}