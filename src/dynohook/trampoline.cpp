#include "trampoline.h"
#include "memory.h"
#include "decoder.h"

using namespace dyno;

/**
 *  @brief Attempts to allocate the trampoline within +-2GB range of the sourceAddress (and rip-relative memory accesses)
 *
 *	@param sourceAddress address to allocate the trampoline for (usually address where hook is placed)
 *  @param restrictedRelocation [out] true if trampoline could not be allocated within +-2GB range. False otehrwise.
 *	@return pointer to the newly allocated memory page (trampoline)
 */
void* Trampoline::HandleTrampolineAllocation(void* sourceAddress, bool& restrictedRelocation) {
    void* trampoline = nullptr;
    Decoder decoder;
    // if we can allocate our trampoline in +-2gb range we only need a 5 bytes JMP
    // if we can't, we need a 14 bytes JMP
    size_t fiveBytesWithoutCuttingInstructions = decoder.getLengthOfInstructions(sourceAddress, 5);
    size_t fourteenBytesWithoutCuttingInstructions = decoder.getLengthOfInstructions(sourceAddress, 14);

#if DYNO_ARCH_X86 == 64
    intptr_t lowestRelativeAddress = 0;
    intptr_t hightestRelativeAddress = 0;

    // attempt using 5 bytes
    if (!decoder.calculateRipRelativeMemoryAccessBounds(sourceAddress, fiveBytesWithoutCuttingInstructions, lowestRelativeAddress, hightestRelativeAddress)) {
        printf("[Error] - Trampoline - Could not calculate bounds of relative instructions replaced by hook!\n");
        return nullptr;
    }

    printf("[Info] - Trampoline - Bounds of relative addresses accessed [%llx, %llx]\n", lowestRelativeAddress, hightestRelativeAddress);

    // check if there was rip-relative memory access
    if (lowestRelativeAddress == 0xffffffffffffffff && hightestRelativeAddress == 0) {
        // there was no rip-relative memory acccess
        // attempt to allocate trampoline within +-2GB range of source address
        trampoline = AllocateTrampoline(sourceAddress, restrictedRelocation);

        if (!trampoline) {
            printf("[Error] - Trampoline - Failed to allocate trampoline for hookAddress %p\n", sourceAddress);
            return nullptr;
        }

        // trampoline could not be allocated withing +-2gb range
        if (restrictedRelocation) {
            // there were no rip-relative memory accesses within fiveBytesWithoutCuttingInstructions of the hook address.
            // since we failed to allocate withing +-2GB range we now need to check fourteenBytesWithoutCuttingInstructions for rip-relative instructions
            if (!decoder.calculateRipRelativeMemoryAccessBounds(sourceAddress, fourteenBytesWithoutCuttingInstructions, lowestRelativeAddress, hightestRelativeAddress)) {
                printf("[Error] - Trampoline - Could not calculate bounds of relative instructions replaced by hook!\n");
                return nullptr;
            }

            // check if there is rip-relative memory access. Since we need to use a fourteenBytesWithoutCuttingInstructions byte jump we don't support relocating rip-relative instructions
            // if we have rip-relativ memory access here, hooking failed
            if (lowestRelativeAddress == 0xffffffffffffffff && hightestRelativeAddress == 0) {
                printf("[Error] - Trampoline - The trampoline could not be allocated withing +-2GB range. The instructions at the hook address do contain rip-relative memory access. Relocating those is not supported when the trampoline is not in +-2GB range!\n");
                return nullptr;
            }
        }
    } else {
        // there was rip-relative memory access (x64 only)
        trampoline = AllocateTrampolineWithinBounds(sourceAddress, lowestRelativeAddress, hightestRelativeAddress, restrictedRelocation);

        if (!trampoline) {
            printf("[Error] - Trampoline - Failed to allocate trampoline within bounds [%llx, %llx]\n", lowestRelativeAddress, hightestRelativeAddress);
            return nullptr;
        }

        // we know there is rip-relative memory access within fiveBytesWithoutCuttingInstructions bytes of the hooking address which is supported
        // if we failed to allocate the trampoline withing +-2GB range it is not supported
        if (restrictedRelocation) {
            printf("[Error] - Trampoline - The trampoline could not be allocated withing +-2GB range. The instructions at the hook address do contain rip-relative memory access. Relocating those is not supported when the trampoline is not in +-2GB range!\n");
            return nullptr;
        }
    }
#elif DYNO_ARCH_X86 == 32
    trampoline = AllocateTrampoline(sourceAddress, restrictedRelocation);
    if (!trampoline) {
        printf("[Error] - Trampoline - Failed to allocate trampoline for hookAddress %p\n", sourceAddress);
        return nullptr;
    }
#endif // DYNO_ARCH_X86
    return trampoline;
}

/**
 *  @brief Attempts to allocate the trampoline within +-2GB range of the sourceAddress
 *
 *	@param sourceAddress address to allocate the trampoline for (usually address where hook is placed)
 *  @param restrictedRelocation [out] true if trampoline could not be allocated within +-2GB range. False otherwise.
 *	@return pointer to the newly allocated memory page (trampoline)
 */
void* Trampoline::AllocateTrampoline(void* sourceAddress, bool& restrictedRelocation) {
    // we attempt to use a rel32 JMP as this allows to relocate RIP-relative memory accesses conveniently
    const int32_t signedIntMaxValue = 0x7fffffff;

    // allocate the trampoline_. We need to allocate this first so we know how many bytes we need to overwrite (5 or 14 Bytes)
    int32_t pageSize = Memory::GetPageSize();
    intptr_t allocationAttempts = 0;

    // calculate the lowest and highest address than can be reached by a jmp rel32 when placing it at the hookAddress
    intptr_t lowestAddressReachableByFiveBytesJump = (intptr_t)sourceAddress - signedIntMaxValue + 5;
    if (lowestAddressReachableByFiveBytesJump < 0)
        lowestAddressReachableByFiveBytesJump = 0;

    printf("[Info] - Trampoline - Attempting to allocate trampoline within +-2GB range of %p\n", sourceAddress);
    void* trampoline = nullptr;
    while (!trampoline) {
#if DYNO_ARCH_X86 == 64
        // start with the highest possible address and go down by one pageSize for every attempt. VirtualAlloc rounds down to nearest multiple of allocation granularity.
        // we start by substracting 1 page (++allocationAttempts) to account for VirtualAlloc rounding down the target address to the next page boundary
        intptr_t targetAddress = (intptr_t)sourceAddress + signedIntMaxValue + 5 - (++allocationAttempts * pageSize);
#elif DYNO_ARCH_X86 == 32
        // for 32 bit only addresses up to 0x7fffffff are in user mode and we can only allocate user mode memory
        intptr_t targetAddress = signedIntMaxValue - ++allocationAttempts * pageSize;
#endif // DYNO_ARCH_X86

        // check if the target address can still be reached with rel32. If the target address is too low, we failed to allocate it withing JMP rel32 range.
        if ((intptr_t)targetAddress >= lowestAddressReachableByFiveBytesJump) {
            // attempt to allocate the trampoline. If we fail, we try again on the next loop iteration.
            // we don't need to worry if our targetAddress is high enough because we start at the highest value that we can use and move down
            trampoline = Memory::AllocateMemory((int8_t*)targetAddress, pageSize);
        } else {
#if DYNO_ARCH_X86 == 64
            // if we couldn't allocate within +-2GB range let the system allocate the memory page anywhere and use and absolute jump. JMP [RIP+0] 0x1122334455667788 (14 Bytes)
            trampoline = Memory::AllocateMemory(nullptr, pageSize);

            //we now require 14 bytes at the hook address to write an absolute JMP and we no longer can relocate rip-relative memory accesses
            restrictedRelocation = true;

            printf("[Warning] - Trampoline - Could not allocate trampoline within desired range. We currently can't relocate rip-relative instructions in this case!\n");

            return trampoline;

#elif DYNO_ARCH_X86 == 32
            restrictedRelocation = false;
            // we currently have no way to deal with situation in 32 Bits. I never observed this to be an issue though. There may be a guarantee that this never happens?
            return nullptr;
#endif // DYNO_ARCH_X86
            restrictedRelocation = false;
            // this should not be reached
            return nullptr;
        }
    }
    printf("[Info] - Trampoline - Allocated trampoline at %p (using %lld attempts)\n", trampoline, allocationAttempts);
    restrictedRelocation = false;
    return trampoline;
}

/**
 * @brief Attempts to allocate a trampoline_ within +-2gb range with respect to rip-relative memory accesses.
 */
void* Trampoline::AllocateTrampolineWithinBounds(void* sourceAddress, intptr_t lowestRipRelativeMemoryAccess, intptr_t highestRipRelativeMemoryAddress, bool& restrictedRelocation) {
    const int32_t signedIntMaxValue = 0x7fffffff;

    // allocate the trampoline_. We need to allocate this first so we know how many bytes we need to overwrite (5 or 14 Bytes)
    int32_t pageSize = Memory::GetPageSize();
    intptr_t allocationAttempts = 0;

    // the size of the static part of the trampoline is 467 Bytes. Additionally relocated Bytes are appended to the trampoline. The length of these instructions depends on the instructions relocated.
    // relocated instructions can be longer than the original ones. At the time of writing this the worst case is jcc from 2 Bytes to 18 Bytes when relocated.
    // the value here is just an upper bound that allows to double the size of the trampoline
    const int trampolineLengthUpperBound = 1000;

    // calculate the lowest and highest address than can be reached by a jmp rel32 when placing it at the hookAddress
    intptr_t lowestAddressReachableByFiveBytesJump = (intptr_t)sourceAddress - signedIntMaxValue + 5;
    if (lowestAddressReachableByFiveBytesJump < 0)
        lowestAddressReachableByFiveBytesJump = 0;

    intptr_t highestAddressReachableByFiveBytesJump = (intptr_t)sourceAddress + signedIntMaxValue + 5;

    intptr_t lowestAddressThatCanReachHighestRipRelativeAccess = highestRipRelativeMemoryAddress - signedIntMaxValue + 5;

    // calculate the highest address that can still reach the lowest rip-relative access
    intptr_t highestAddressThatCanReachLowestRipRelativeAccess = lowestRipRelativeMemoryAccess + signedIntMaxValue - 5;

    // we want to start allocation attempts with the highest address that can reach the lowest rip-relative memory access and is reachable with jmp rel32 from the hook address
    intptr_t initialTargetAddress = highestAddressThatCanReachLowestRipRelativeAccess;
    if (initialTargetAddress > highestAddressReachableByFiveBytesJump)
        initialTargetAddress = highestAddressReachableByFiveBytesJump;

    printf("[Info] - Trampoline - Attempting to allocate trampoline within +-2GB range of [%llx, %llx] with a trampoline maximum size of %d\n", lowestRipRelativeMemoryAccess, highestRipRelativeMemoryAddress, trampolineLengthUpperBound);
    void* trampoline = nullptr;
    while (!trampoline) {
        // allocation attempts are started from the highest possible address to the lowest. We substract pageSize to account for VirtualAlloc rounding down the target address to the next page boundary.
        // start with highest address that can both:
        // - reach lowest RIP-relative
        // - can be reached by jmp rel32
        int8_t* targetAddress = (int8_t*)initialTargetAddress - trampolineLengthUpperBound - (++allocationAttempts * pageSize);

        // check if we are still high enough
        // we know we failed to allocate with rel32 when one of these statements is true:
        // - address is to low to be reached by rel32
        // - address is to low to reach highestRipRelativeMemoryAccess
        if ((intptr_t) targetAddress >= lowestAddressReachableByFiveBytesJump &&
            (intptr_t) targetAddress >= lowestAddressThatCanReachHighestRipRelativeAccess) {
            // try to allocate trampoline_ within "JMP rel32" range so we can hook by overwriting 5 Bytes instead of 14 Bytes
            // we don't need to worry if our targetAddress is high enough because we start at the highest value that we can use and move down
            // if the call with this target address fails we keep trying
            trampoline = Memory::AllocateMemory(targetAddress, pageSize);
        } else {
#if DYNO_ARCH_X86 == 64
            // if we couldn't allocate within +-2GB range let the system allocate the memory page anywhere and use and absolute jump. JMP [RIP+0] 0x1122334455667788 (14 Bytes)
            trampoline = Memory::AllocateMemory(nullptr, pageSize);

            // we now require 14 bytes at the hook address to write an absolute JMP and we no longer can relocate rip-relative memory accesses
            restrictedRelocation = true;

            printf("[Warning] - Trampoline - Could not allocate trampoline within desired range. We currently can't relocate rip-relative instructions in this case!\n");
            return trampoline;

#elif DYNO_ARCH_X86 == 32
            restrictedRelocation = false;
            // we currently have no way to deal with this situation in 32 Bits. I never observed this to be an issue though. There may be a guarantee that this never happens?
            return nullptr;
#endif // DYNO_ARCH_X86
            // this should not be reached
            restrictedRelocation = false;
            return nullptr;
        }
    }
    printf("[Info] - Trampoline - Allocated trampoline at %p (using %lld attempts)\n", trampoline, allocationAttempts);
    restrictedRelocation = false;
    return trampoline;
}