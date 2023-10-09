#include "vhook.h"

using namespace dyno;

bool VHook::hook() {
    assert(!m_hooked);
    if (m_hooked) {
        LOG_PRINT("Vhook failed: hook already present");
        return false;
    }
    // create the bridge function
    if (!createBridge()) {
        LOG_PRINT("Failed to create bridge");
        return false;
    }
    m_hooked = true;
    return true;
}

bool VHook::unhook() {
    assert(m_hooked);
    if (!m_hooked) {
        LOG_PRINT("Vhook failed: no hook present");
        return false;
    }
    m_hooked = false;
    // restore should be handled by holder
    return true;
}