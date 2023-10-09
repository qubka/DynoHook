#include "vtable.h"
#include "memory.h"
#include "mem_protector.h"

using namespace dyno;

VTable::VTable(void* pClass) : m_class((void***)pClass) {
	MemProtector protector{(uintptr_t)m_class, sizeof(void*), ProtFlag::R | ProtFlag::W, *this};

    m_origVtable = *m_class;
    m_vFuncCount = getVFuncCount(m_origVtable);
    m_newVtable = std::make_unique<void*[]>(m_vFuncCount);
    std::memcpy(m_newVtable.get(), m_origVtable, sizeof(void*) * m_vFuncCount);
    *m_class = m_newVtable.get();
}

VTable::~VTable() {
	MemProtector protector{(uintptr_t)m_class, sizeof(void*), ProtFlag::R | ProtFlag::W, *this};

    *m_class = m_origVtable;
}

size_t VTable::getVFuncCount(void** vtable) {
    size_t count = 0;
    while (true) {
        // if you have more than 500 vfuncs you have a problem
        if (!isValidPtr(vtable[++count]) || count > 500)
            break;
    }
    return count;
}

Hook* VTable::hook(const HookSupplier& supplier, size_t index) {
    auto it = m_hooked.find(index);
    if (it != m_hooked.end())
        return it->second.get();

    if (index >= m_vFuncCount) {
        LOG_PRINT("Invalid virtual function index");
        return nullptr;
    }

	auto vhook = supplier(m_origVtable[index]);
	if (!vhook) {
		LOG_PRINT("Invalid virtual hook");
		return nullptr;
	}
	
    VHook* hook = m_hooked.emplace(index, std::move(vhook)).first->second.get();
    m_newVtable[index] = (void*) hook->getBridge();
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