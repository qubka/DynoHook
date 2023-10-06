#include "manager.h"
#include "detour.h"

using namespace dyno;

Hook* HookManager::hook(void* pFunc, const ConvFunc& convention) {
    if (!pFunc)
        return nullptr;

    Hook* hook = find(pFunc);
    if (hook)
        return hook;

	std::lock_guard<std::mutex> m_lock{m_mutex};

	auto detour = std::make_unique<Detour>((uintptr_t)pFunc, convention);
	if (!detour->hook())
		return nullptr;
    return m_detours.emplace_back(std::move(detour)).get();
}

Hook* HookManager::hook(void* pClass, size_t index, const ConvFunc& convention) {
    if (!pClass)
        return nullptr;

    Hook* hook = find(pClass, index);
    if (hook)
        return hook;

	std::lock_guard<std::mutex> m_lock{m_mutex};
	
    HookSupplier supplier = [&](void* pFunc) {
        auto it = m_vhooks.find(pFunc);
        if (it != m_vhooks.end())
            return it->second;
		auto vhook = std::make_shared<VHook>((uintptr_t)pFunc, convention);
		if (!vhook->hook())
			return nullptr;
		return m_vhooks.emplace(pFunc, std::move(vhook)).first->second;
    };

    for (auto& table : m_vtables) {
        if (*table == pClass)
            return table->hook(supplier, index);
    }

    auto vtable = std::make_unique<VTable>(pClass);
    hook = vtable->hook(supplier, index);
    if (hook) m_vtables.push_back(std::move(vtable));
    return hook;
}

bool HookManager::unhook(void* pFunc) {
    if (!pFunc)
        return false;

	std::lock_guard<std::mutex> m_lock{m_mutex};

    for (size_t i = 0; i < m_detours.size(); ++i) {
        auto& detour = m_detours[i];
        if (*detour == pFunc) {
            m_detours.erase(m_detours.begin() + i);
            return true;
        }
    }

    return false;
}

bool HookManager::unhook(void* pClass, size_t index) {
    if (!pClass)
        return false;

	std::lock_guard<std::mutex> m_lock{m_mutex};
	
    for (size_t i = 0; i < m_vtables.size(); ++i) {
        auto& table = m_vtables[i];
        if (*table == pClass) {
            if (table->unhook(index)) {
                if (table->empty())
                    m_vtables.erase(m_vtables.begin() + i);
                return true;
            }
            return false;
        }
    }

    return false;
}

Hook* HookManager::find(void* pFunc) const {
    if (!pFunc)
        return nullptr;

    for (auto& detour : m_detours) {
        if (*detour == pFunc)
            return detour.get();
    }

    return nullptr;
}

Hook* HookManager::find(void* pClass, size_t index) const {
    if (!pClass)
        return nullptr;

    for (auto& table : m_vtables) {
        if (*table == pClass)
            return table->find(index);
    }

    return nullptr;
}

void HookManager::unhookAll() {
	std::lock_guard<std::mutex> m_lock{m_mutex};
	
    m_detours.clear();
    m_vtables.clear();
    m_vhooks.clear();
}

void HookManager::unhookAll(void* pClass) {
    if (!pClass)
        return;
	
	std::lock_guard<std::mutex> m_lock{m_mutex};

    for (size_t i = 0; i < m_vtables.size(); ++i) {
        auto& table = m_vtables[i];
        if (*table == pClass) {
            m_vtables.erase(m_vtables.begin() + i);
            return;
        }
    }
}

void HookManager::clearCache() {
	std::lock_guard<std::mutex> m_lock{m_mutex};
	
    auto it = m_vhooks.cbegin();
    while (it != m_vhooks.cend()) {
        if (it->second.use_count() == 1) {
            it = m_vhooks.erase(it);
        } else {
            ++it;
        }
    }
}

HookManager& HookManager::Get() {
    static HookManager s_manager;
    return s_manager;
}