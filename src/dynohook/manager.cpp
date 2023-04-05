#include "manager.hpp"

using namespace dyno;

HookManager::HookManager() : m_Jit{} {
}

HookManager::~HookManager() {
    for (Hook* hook : m_Hooks)
        delete hook;
}

Hook* HookManager::hook(void* func, ICallingConvention* convention) {
    if (!func)
        return nullptr;

    Hook* hook = find(func);
    if (hook) {
        delete convention;
        return hook;
    }

    hook = new Hook{m_Jit, func, convention};
    m_Hooks.push_back(hook);
    return hook;
}

void HookManager::unhook(void* func) {
    if (!func)
        return;

    for (size_t i = 0; i < m_Hooks.size(); ++i) {
        Hook* hook = m_Hooks[i];
        if (hook->m_pFunc == func) {
            m_Hooks.erase(m_Hooks.begin() + i);
            delete hook;
            return;
        }
    }
}

Hook* HookManager::find(void* func) const {
    if (!func)
        return nullptr;

    for (Hook* hook : m_Hooks) {
        if (hook->m_pFunc == func)
            return hook;
    }

    return nullptr;
}

void HookManager::unhookAll() {
    for (Hook* hook : m_Hooks)
        delete hook;

    m_Hooks.clear();
}

HookManager& HookManager::Get() {
    static HookManager s_Manager;
    return s_Manager;
}