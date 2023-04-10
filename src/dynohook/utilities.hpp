#pragma once

namespace dyno {
    size_t WriteRelativeJump(void* targetAddr, void* addrToJumpTo);

    size_t WriteAbsoluteJump(void* targetAddr, void* addrToJumpTo);

    std::pair<uint32_t, bool> BuildTrampoline(void* func2hook, void* dstMemForTrampoline, std::vector<uint8_t>& dstOriginalInstructions);
}