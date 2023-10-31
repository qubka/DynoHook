#include "vhook.h"

using namespace dyno;

VHook::VHook(uintptr_t fnAddress, const ConvFunc& convention) : Hook{convention}, m_fnAddress{fnAddress} {
    assert(fnAddress != 0 && "Function address cannot be null");
}

VHook::~VHook() {
    if (m_hooked) {
        unhook();
    }
}

bool VHook::hook() {
    assert(!m_hooked);
    if (m_hooked) {
        DYNO_LOG("Vhook failed: hook already present", ErrorLevel::WARN);
        return false;
    }
    // create the bridge function
    if (!createBridge()) {
        DYNO_LOG("Failed to create bridge", ErrorLevel::SEV);
        return false;
    }
    m_hooked = true;
    return true;
}

bool VHook::unhook() {
    assert(m_hooked);
    if (!m_hooked) {
        DYNO_LOG("Vhook failed: no hook present", ErrorLevel::SEV);
        return false;
    }
    m_hooked = false;
    // restore should be handled by holder
    return true;
}