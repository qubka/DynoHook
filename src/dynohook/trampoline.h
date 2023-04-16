#pragma once

namespace dyno {
    /**
	 * @brief Allocates trampolines and provides information about it.
	 */
    class Trampoline {
    public:
        static void* HandleTrampolineAllocation(void* sourceAddress, bool& restrictedRelocation);
        static void* AllocateTrampoline(void* sourceAddress, bool& restrictedRelocation);
        static void* AllocateTrampolineWithinBounds(void* sourceAddress, int64_t lowestRipRelativeMemoryAccess, int64_t highestRipRelativeMemoryAddress, bool& restrictedRelocation);
    };
}