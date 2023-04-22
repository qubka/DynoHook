#include "vthook.h"
#include "memory.h"

using namespace dyno;

VHook::VHook(asmjit::JitRuntime* jit, void* pClass) : m_jit(jit), m_class((void***)pClass) {
    MemoryProtect protector(m_class, sizeof(void*), RWX);

    m_origVtable = *m_class;
    m_vFuncCount = GetVFuncCount(m_origVtable);
    m_newVtable = std::make_unique<void*[]>(m_vFuncCount);
    std::memcpy(m_newVtable.get(), m_origVtable, sizeof(void*) * m_vFuncCount);
    *m_class = m_newVtable.get();
}

VHook::~VHook() {
    MemoryProtect protector(m_class, sizeof(void*), RWX);
    *m_class = m_origVtable;
}

size_t VHook::GetVFuncCount(void** vtable) {
    size_t count = 0;
    for (; ; count++) {
        if (!IsValidPtr(vtable[count]))
            break;
    }
    return count;
}

Hook* VHook::hook(size_t index, CallingConvention* convention) {
    if (m_hookedFunc.find(index) != m_hookedFunc.end())
        return nullptr;

    VTHook* hook = m_hookedFunc.emplace(index, std::make_unique<VTHook>(m_origVtable[index], m_jit, convention)).first->second.get();
    m_newVtable[index] = hook->m_bridge;
    return hook;
}

void VHook::unhook(size_t index) {
    if (m_hookedFunc.find(index) == m_hookedFunc.end())
        return;

    m_hookedFunc.erase(index);
    m_newVtable[index] = m_origVtable[index];
}

Hook* VHook::find(size_t index) {
    auto it = m_hookedFunc.find(index);
    return it != m_hookedFunc.end() ? it->second.get() : nullptr;
}

VHook::VTHook::VTHook(void* original, asmjit::JitRuntime* jit, CallingConvention* convention) : Hook(jit, convention) {
    // create the bridge function
    if (!createBridge(original)) {
        printf("[Error] - Hook - Failed to create bridge\n");
        return;
    }
}
