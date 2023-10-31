#include "manager.h"

using namespace dyno;

std::shared_ptr<Hook> HookManager::hook(void* pFunc, const ConvFunc& convention) {
    if (!pFunc)
        return nullptr;

    std::lock_guard<std::mutex> m_lock{m_mutex};

    auto it = m_detours.find(pFunc);
    if (it != m_detours.end())
        return it->second;

	auto detour = std::make_shared<NatDetour>((uintptr_t)pFunc, convention);
	if (!detour->hook())
		return nullptr;

    m_detours.emplace(pFunc, detour);
    return detour;
}

std::shared_ptr<Hook> HookManager::hook(void* pClass, size_t index, const ConvFunc& convention) {
    if (!pClass)
        return nullptr;

    std::lock_guard<std::mutex> m_lock{m_mutex};

    auto it = m_vtables.find(pClass);
    if (it != m_vtables.end())
        return it->second->hook(index, convention);

    auto vtable = std::make_unique<VTable>(pClass, m_cache);
    auto hook = vtable->hook(index, convention);
    if (hook) m_vtables.emplace(pClass, std::move(vtable));
    return hook;
}

bool HookManager::unhook(void* pFunc) {
    if (!pFunc)
        return false;

	std::lock_guard<std::mutex> m_lock{m_mutex};

    auto it = m_detours.find(pFunc);
    if (it != m_detours.end()) {
        m_detours.erase(it);
        return true;
    }

    return false;
}

bool HookManager::unhook(void* pClass, size_t index) {
    if (!pClass)
        return false;

	std::lock_guard<std::mutex> m_lock{m_mutex};

    auto it = m_vtables.find(pClass);
    if (it != m_vtables.end()) {
        auto& table = it->second;
        if (table->unhook(index)) {
            if (table->empty())
                m_vtables.erase(it);
            return true;
        }

        return false;
    }

    return false;
}

std::shared_ptr<Hook> HookManager::find(void* pFunc) const {
    auto it = m_detours.find(pFunc);
    return it != m_detours.end() ? it->second : nullptr;
}

std::shared_ptr<Hook> HookManager::find(void* pClass, size_t index) const {
    auto it = m_vtables.find(pClass);
    return it != m_vtables.end() ? it->second->find(index) : nullptr;
}

void HookManager::unhookAll() {
	std::lock_guard<std::mutex> m_lock{m_mutex};

    m_detours.clear();
    m_vtables.clear();
    m_cache.clear();
}

void HookManager::unhookAll(void* pClass) {
    if (!pClass)
        return;

    std::lock_guard<std::mutex> m_lock{m_mutex};

    auto it = m_vtables.find(pClass);
    if (it != m_vtables.end())
        m_vtables.erase(it);
}

void HookManager::clearCache() {
	std::lock_guard<std::mutex> m_lock{m_mutex};

    m_cache.remove();
}

HookManager& HookManager::Get() {
    static HookManager s_manager;
    return s_manager;
}