#include "vtable.h"
#include "memory.h"

using namespace dyno;

VTable::VTable(void* pClass) : m_class((void***)pClass) {
    MemoryProtect protector(m_class, sizeof(void*), RWX);

    m_origVtable = *m_class;
    m_vFuncCount = GetVFuncCount(m_origVtable);
    m_newVtable = std::make_unique<void*[]>(m_vFuncCount);
    std::memcpy(m_newVtable.get(), m_origVtable, sizeof(void*) * m_vFuncCount);
    *m_class = m_newVtable.get();
}

VTable::~VTable() {
    MemoryProtect protector(m_class, sizeof(void*), RWX);

    *m_class = m_origVtable;
}

size_t VTable::GetVFuncCount(void** vtable) {
    size_t count = 0;
    while (true) {
        if (!IsValidPtr(vtable[++count]))
            break;
    }
    return count;
}

Hook* VTable::hook(const HookSupplier& supplier, size_t index) {
    auto it = m_hooked.find(index);
    if (it != m_hooked.end())
        return it->second.get();

    if (index >= m_vFuncCount) {
        puts("[Error] - VTable - Invalid virtual function index");
        return nullptr;
    }

    VTHook* hook = m_hooked.emplace(index, supplier(m_origVtable[index])).first->second.get();
    m_newVtable[index] = hook->getBridge();
    return hook;
}

bool VTable::unhook(size_t index) {
    auto it = m_hooked.find(index);
    if (it == m_hooked.end())
        return false;

    m_hooked.erase(it);
    m_newVtable[index] = m_origVtable[index];
    return true;
}

Hook* VTable::find(size_t index) const {
    auto it = m_hooked.find(index);
    return it != m_hooked.end() ? it->second.get() : nullptr;
}