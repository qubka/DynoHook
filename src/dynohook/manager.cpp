#include "manager.h"
#include "detour.h"

#include <asmjit/asmjit.h>

using namespace dyno;

HookManager::HookManager() : m_jit(new asmjit::JitRuntime()) {
}

HookManager::~HookManager() {
    delete m_jit;
}

Hook* HookManager::hook(void* pFunc, CallingConvention* convention) {
    if (!pFunc)
        return nullptr;

    Hook* hook = find(pFunc);
    if (hook) {
        delete convention;
        return hook;
    }

    return m_detours.emplace_back(std::make_unique<Detour>(pFunc, convention)).get();
}

Hook* HookManager::hook(void* pClass, size_t index, CallingConvention* convention) {
    if (!pClass)
        return nullptr;

    Hook* hook = find(pClass, index);
    if (hook) {
        delete convention;
        return hook;
    }

    VHook* vhook = nullptr;

    for (auto& h : m_vhooks) {
        if (h->m_class == (void***) pClass) {
            vhook = h.get();
            break;
        }
    }

    if (vhook == nullptr)
        vhook = m_vhooks.emplace_back(std::make_unique<VHook>(m_jit, pClass)).get();

    return vhook->hook(index, convention);
}

void HookManager::unhook(void* pFunc) {
    if (!pFunc)
        return;

    for (size_t i = 0; i < m_detours.size(); ++i) {
        auto& detour = m_detours[i];
        if (detour->m_func == pFunc) {
            m_detours.erase(m_detours.begin() + i);
            return;
        }
    }
}

Hook* HookManager::find(void* pFunc) const {
    if (!pFunc)
        return nullptr;

    for (auto& h : m_detours) {
        if (h->m_func == pFunc)
            return h.get();
    }

    return nullptr;
}

Hook* HookManager::find(void* pClass, size_t index) const {
    if (!pClass)
        return nullptr;

    for (auto& h : m_vhooks) {
        if (h->m_class == pClass)
            return h->find(index);
    }

    return nullptr;
}

void HookManager::unhookAll() {
    m_detours.clear();
    m_vhooks.clear();
}

HookManager& HookManager::Get() {
    static HookManager s_Manager;
    return s_Manager;
}

