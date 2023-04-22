#pragma once

#include "convention.h"
#include "hook.h"
#include "vthook.h"
#include "detour.h"

namespace dyno {
    class HookManager {
    private:
        HookManager();
        ~HookManager();

    public:
        NONCOPYABLE(HookManager);

        /**
         * @brief Hooks the given function and returns a new Hook instance.
         * If the function was already hooked, the existing Hook instance will be returned.
         * @param pFunc
         * @param convention
         * @return
         */
        Hook* hook(void* pFunc, CallingConvention* convention);

        Hook* hook(void* pClass, size_t index, CallingConvention* convention);

        /**
         * @brief Removes all callbacks and restores the original function.
         * @param pFunc
         */
        void unhook(void* pFunc);

        void unhook(void* pClass, size_t index);

        /**
         * @brief Returns either NULL or the found Hook instance.
         * @param pFunc
         * @return
         */
        Hook* find(void* pFunc) const;

        Hook* find(void* pClass, size_t index) const;

        /**
         * @brief Removes all callbacks and restores all functions.
         */
        void unhookAll();

        /**
         * @brief Returns a pointer to a static HookManager object.
         * @return
         */
        static HookManager& Get();

    public:
        std::vector<std::unique_ptr<Detour>> m_detours;
        std::vector<std::unique_ptr<VHook>> m_vhooks;

        asmjit::JitRuntime* m_jit;
    };
}