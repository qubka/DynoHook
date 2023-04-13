#pragma once

#include "hook.hpp"
#include "convention.hpp"

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
         * @param func
         * @param convention
         * @return
         */
        Hook* hook(void* func, ICallingConvention* convention);

        /**
         * @brief Removes all callbacks and restores the original function.
         * @param func
         */
        void unhook(void* func);

        /**
         * @brief Returns either NULL or the found Hook instance.
         * @param func
         * @return
         */
        Hook* find(void* func) const;

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
        std::vector<Hook*> m_hooks;

        // Runtime designed for JIT - it holds relocated functions and controls their lifetime.
        asmjit::JitRuntime* m_jit;
    };
}