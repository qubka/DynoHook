#include "vthook.h"
#include "memory.h"
#include "trampoline.h"

using namespace dyno;

VTHook::VTHook(void* pFunc, const ConvFunc& convention) : m_func(pFunc), Hook(convention) {
    // allocate space for bridge and ret functions
    bool restrictedRelocation;
    m_page = Trampoline::HandleTrampolineAllocation(m_func, restrictedRelocation);

    // we don't use JitAllocator, instead using page which we allocated near our hooked function
    m_bridge = (uint8_t*) m_page;
    m_newRetAddr = (uint8_t*) m_page + Memory::GetPageSize() / 2;

    // create the bridge function
    if (!createBridge()) {
        puts("[Error] - VTHook - Failed to create bridge");
        return;
    }
}

VTHook::~VTHook() {
    Memory::FreeMemory(m_page, 0);
}