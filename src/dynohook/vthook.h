#pragma once

#include "hook.h"

namespace dyno {
    class VHook {
        friend class HookManager;
    public:
        VHook(asmjit::JitRuntime* jit, void* pClass);
        ~VHook();

        Hook* hook(size_t index, CallingConvention* convention);
        void unhook(size_t index);

        Hook* find(size_t index);

    private:
        class VTHook : public Hook {
        public:
            VTHook(void* original, asmjit::JitRuntime* jit, CallingConvention* convention);
        };

        static size_t GetVFuncCount(void** vtable);

        asmjit::JitRuntime* m_jit;

        std::unique_ptr<void*[]> m_newVtable;
        void** m_origVtable;
        void*** m_class;
        size_t m_vFuncCount;
        std::map<size_t, std::unique_ptr<VTHook>> m_hookedFunc;
    };
}
