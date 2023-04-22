#include "detour.h"
#include "trampoline.h"
#include "decoder.h"
#include "memory.h"

using namespace dyno;

Detour::Detour(void* pFunc, CallingConvention* convention) : m_func(pFunc), m_hookLength(0), Hook(nullptr, convention) {
    // allocate space for stub + space for overwritten bytes + jumpback
    bool restrictedRelocation;
    m_trampoline = Trampoline::HandleTrampolineAllocation(m_func, restrictedRelocation);
    if (!m_trampoline) {
        printf("[Error] - Hook - Failed to allocate trampoline\n");
        return;
    }

    // create the bridge function
    if (!createBridge(m_trampoline)) {
        printf("[Error] - Hook - Failed to create bridge\n");
        return;
    }

    // create the trampoline function
    if (!createTrampoline(restrictedRelocation)) {
        printf("[Error] - Hook - Failed to create trampoline\n");
        return;
    }
}

Detour::~Detour() {
    // probably hook wasn't generated successfully
    if (m_hookLength == 0)
        return;

    // allow to write and read
    MemoryProtect protector(m_func, m_hookLength, RWX);

    // copy back the previously copied bytes
    std::memcpy(m_func, m_originalBytes.get(), m_hookLength);

    // free trampoline memory page
    Memory::FreeMemory(m_trampoline, 0);
}

bool Detour::createTrampoline(bool restrictedRelocation) {
    uint8_t* sourceAddress = (uint8_t*) m_func;
    uint8_t* targetAddress = (uint8_t*) m_bridge;

    Decoder decoder;
#if DYNO_ARCH_X86 == 64
    int64_t addressDelta = (int64_t)targetAddress - (int64_t)sourceAddress;
    if (addressDelta > INT32_MAX || addressDelta < INT32_MIN)
        m_hookLength = decoder.getLengthOfInstructions(sourceAddress, 14);
    else
#endif
        m_hookLength = decoder.getLengthOfInstructions(sourceAddress, 5);

    // 5 bytes are required to place detour
    assert(m_hookLength >= 5);

    // save original bytes
    m_originalBytes = std::make_unique<uint8_t[]>(m_hookLength);
    std::memcpy(m_originalBytes.get(), sourceAddress, m_hookLength);

    // make page of detour address writeable
    MemoryProtect protector(m_func, m_hookLength, RWX);

    // relocate to be overwritten instructions to trampoline
    auto relocatedBytes = decoder.relocate(sourceAddress, m_hookLength, m_trampoline, restrictedRelocation);
    if (relocatedBytes.empty()) {
        printf("[Error] - Hook - Relocation of bytes replaced by hook failed\n");
        return false;
    }

    // copy overwritten bytes to trampoline
    std::memcpy(m_trampoline, relocatedBytes.data(), relocatedBytes.size());

    uint8_t* addressAfterRelocatedBytes = (uint8_t*) m_trampoline + relocatedBytes.size();

    // length of jmp rel32
    size_t jmpToHookedFunctionLength = 5;

#if DYNO_ARCH_X86 == 64
    // write JMP back from trampoline to original code
    addressAfterRelocatedBytes[0] = 0xFF;														//opcodes = JMP [rip+0]
    addressAfterRelocatedBytes[1] = 0x25;														//opcodes = JMP [rip+0]
    *(int32_t*)(&addressAfterRelocatedBytes[2]) = 0;											//relative distance from RIP (+0)
    *(int64_t*)(&addressAfterRelocatedBytes[2 + 4]) = (int64_t)(sourceAddress + m_hookLength);	//destination to jump to

    // check if a jmp rel32 can reach
    if (addressDelta > INT32_MAX || addressDelta < INT32_MIN) {
        // need absolute 14 byte jmp
        jmpToHookedFunctionLength = 14;
        // write JMP from original code to hook function
        sourceAddress[0] = 0xFF;																//opcodes = JMP [rip+0]
        sourceAddress[1] = 0x25;																//opcodes = JMP [rip+0]
        *(int32_t*)(&sourceAddress[2]) = 0;														//relative distance from RIP (+0)
        *(int64_t*)(&sourceAddress[2 + 4]) = (int64_t)(targetAddress);							//destination to jump to
    } else {
        // jmp rel32 is enough
        sourceAddress[0] = 0xE9;																//JMP rel32
        *(int32_t*)(&sourceAddress[1]) = (int32_t)((int64_t)targetAddress - (int64_t)sourceAddress - 5);
    }
#elif DYNO_ARCH_X86 == 32
    // write JMP back from trampoline to original code
    addressAfterRelocatedBytes[0] = 0xE9;
    *(int32_t*)(addressAfterRelocatedBytes + 1) = (int32_t)(sourceAddress + hookLength - addressAfterRelocatedBytes) - 5;

    // write JMP from original code to hook function
    sourceAddress[0] = 0xE9;
    *(int32_t*)(sourceAddress + 1) = (int32_t)(targetAddress - sourceAddress) - 5;
#endif // DYNO_ARCH_X86

    // NOP left over bytes
    for (size_t i = jmpToHookedFunctionLength; i < m_hookLength; i++)
        sourceAddress[i] = 0x90;

    return true;
}