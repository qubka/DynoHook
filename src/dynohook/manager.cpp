#include "manager.hpp"

using namespace dyno;

HookManager::HookManager() : m_jit{} {
}

HookManager::~HookManager() {
    for (Hook* hook : m_hooks)
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

    hook = new Hook{m_jit, func, convention};
    m_hooks.push_back(hook);
    return hook;
}

void HookManager::unhook(void* func) {
    if (!func)
        return;

    for (size_t i = 0; i < m_hooks.size(); ++i) {
        Hook* hook = m_hooks[i];
        if (hook->m_func == func) {
            m_hooks.erase(m_hooks.begin() + i);
            delete hook;
            return;
        }
    }
}

Hook* HookManager::find(void* func) const {
    if (!func)
        return nullptr;

    for (Hook* hook : m_hooks) {
        if (hook->m_func == func)
            return hook;
    }

    return nullptr;
}

void HookManager::unhookAll() {
    for (Hook* hook : m_hooks)
        delete hook;

    m_hooks.clear();
}

HookManager& HookManager::Get() {
    static HookManager s_Manager;
    return s_Manager;
}