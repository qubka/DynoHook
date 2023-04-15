#pragma once

#include "hook.h"
#include "convention.h"

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
        Hook* hook(void* func, CallingConvention* convention);

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
    };
}