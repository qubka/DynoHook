#pragma once

#include "convention.h"
#include "_hook.h"
#include "virtuals/vtable.h"
#include "detours/nat_detour.h"

#include <asmjit/asmjit.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <dynohook_export.h>

namespace dyno {

    class DYNO_API HookManager {
    private:
        HookManager();
        ~HookManager() = default;

    public:
        DYNO_NONCOPYABLE(HookManager);

        /**
         * @brief Creates a detour hook for a given function.
         * If the function was already hooked, the existing Hook instance will be returned.
         * @param pFunc address to apply the hook to.
         * @param convention
         * @return NULL or the Hook instance.
         */
        std::shared_ptr<IHook> hookDetour(void* pFunc, const ConvFunc& convention);

        /**
         * @brief Creates a function hook inside the virtual function table.
         * If the function was already hooked, the existing Hook instance will be returned.
         * @param pClass address of the class to instantiate hook on.
         * @param index index of the function to hook inside the virtual function table. (starting at 0)
         * @param convention
         * @return NULL or the Hook instance.
         */
        std::shared_ptr<IHook> hookVirtual(void* pClass, size_t index, const ConvFunc& convention);

        /**
         * @brief Removes all callbacks and restores the original function.
         * @param pFunc address to apply the hook to.
         * @return true if the function was hooked previously and is unhooked now. False otherwhise.
         */
        bool unhookDetour(void* pFunc);

        /**
         * @brief Removes all callbacks and restores the original function.
         * @param pClass address of the class to instantiate hook on.
         * @param index index of the function to hook inside the virtual function table. (starting at 0)
         * @return true if the function was hooked previously and is unhooked now. False otherwhise.
         */
        bool unhookVirtual(void* pClass, size_t index);

        /**
         * @brief Finds the hook for a given function.
         * @param pFunc address to apply the hook to.
         * @return NULL or the found Hook instance.
         */
        std::shared_ptr<IHook> findDetour(void* pFunc) const;

        /**
         * @brief Finds the hook for a given class and virtual function index.
         * @param pClass address of the class to instantiate hook on.
         * @param index index of the function to hook inside the virtual function table. (starting at 0)
         * @return NULL or the found Hook instance.
         */
        std::shared_ptr<IHook> findVirtual(void* pClass, size_t index) const;

        /**
         * @brief Removes all callbacks and restores all functions.
         */
        void unhookAll();

        /**
         * @brief Unhooks all previously hooked functions in the virtual function table.
         * @param pClass address of the class to instantiate hook on.
         */
        void unhookAllVirtual(void* pClass);

        /**
         * @return Returns a pointer to a static HookManager object.
         */
        static HookManager& Get();

    public:
		std::shared_ptr<VHookCache> m_cache;
		std::unordered_map<void*, std::unique_ptr<VTable>> m_vtables;
		std::unordered_map<void*, std::shared_ptr<NatDetour>> m_detours;
        std::mutex m_mutex;
    };
}