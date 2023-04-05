#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    void* AllocateMemory(void* addr, size_t size);

    void FreeMemory(void* addr, size_t size);

    bool ProtectMemory(void* addr, size_t size);

    void* AllocatePageNearAddress(void* targetAddr);

    void FreePage(void* pageAdr);

    size_t WriteRelativeJump32(void* relJumpMemory, void* addrToJumpTo);

    size_t WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo);

    uint32_t BuildTrampoline(void* func2hook, void* dstMemForTrampoline, std::vector<uint8_t>& dstOriginalInstructions);

#ifdef __cplusplus
}
#endif