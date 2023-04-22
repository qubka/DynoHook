#pragma once

#include "hook.h"

namespace dyno {
    class Detour : public Hook {
        friend class HookManager;
    public:
        Detour(void* pFunc, CallingConvention* convention);
        ~Detour() override;

    private:
        bool createTrampoline(bool restrictedRelocation);

    protected:
        // address of the original function
        void* m_func;

        // address of the trampoline
        void* m_trampoline;

        // instructions of the original function
        std::unique_ptr<uint8_t[]> m_originalBytes;

        //
        size_t m_hookLength;
    };
}