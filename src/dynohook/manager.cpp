#include "manager.h"
#include "detour.h"

#include <asmjit/asmjit.h>

using namespace dyno;

Hook* HookManager::hook(void* pFunc, const ConvFunc& convention) {
    if (!pFunc)
        return nullptr;

    Hook* hook = find(pFunc);
    if (hook)
        return hook;

    return m_detours.emplace_back(std::make_unique<Detour>(pFunc, convention)).get();
}

Hook* HookManager::hook(void* pClass, size_t index, const ConvFunc& convention) {
    if (!pClass)
        return nullptr;

    Hook* hook = find(pClass, index);
    if (hook)
        return hook;

    HookSupplier supplier = [&](void* func) {
        auto it = m_vthooks.find(func);
        if (it != m_vthooks.end())
            return it->second;
        return m_vthooks.emplace(func, std::make_shared<VTHook>(func, convention)).first->second;
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
    m_detours.clear();
    m_vtables.clear();
    m_vthooks.clear();
}

void HookManager::unhookAll(void* pClass) {
    if (!pClass)
        return;

    for (size_t i = 0; i < m_vtables.size(); ++i) {
        auto& table = m_vtables[i];
        if (*table == pClass) {
            m_vtables.erase(m_vtables.begin() + i);
            return;
        }
    }
}

void HookManager::clearCache() {
    auto it = m_vthooks.cbegin();
    while (it != m_vthooks.cend()) {
        if (it->second.use_count() == 1) {
            it = m_vthooks.erase(it);
        } else {
            ++it;
        }
    }
}

HookManager& HookManager::Get() {
    static HookManager s_Manager;
    return s_Manager;
}
