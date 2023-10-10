#pragma once

#include "dynohook/virtuals/vhook.h"

namespace dyno {
    typedef std::function<std::shared_ptr<VHook>(void*)> HookSupplier;

    class VTable final : public MemAccessor {
    public:
        explicit VTable(void* pClass);
        ~VTable() override;
        DYNO_NONCOPYABLE(VTable);

        Hook* hook(const HookSupplier& supplier, size_t index);
        bool unhook(size_t index);

        Hook* find(size_t index) const;
        bool empty() const {
            return m_hooked.empty();
        }

        bool operator==(void* pClass) const {
            return m_class == pClass;
        }

    private:
        static size_t getVFuncCount(void** vtable);

        void*** m_class;
        void** m_origVtable;
        size_t m_vFuncCount;
        std::unique_ptr<void*[]> m_newVtable;

        std::map<size_t, std::shared_ptr<VHook>> m_hooked;
    };
}