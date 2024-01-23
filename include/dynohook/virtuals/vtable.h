#pragma once

#include <dynohook/virtuals/vhook.h>

namespace dyno {
    class VHookCache;

    class VTable final : public MemAccessor {
    public:
        VTable(void* pClass, std::shared_ptr<VHookCache> cache);
        ~VTable() override;
        DYNO_NONCOPYABLE(VTable);

        std::shared_ptr<Hook> hook(size_t index, const ConvFunc& convention);
        bool unhook(size_t index);

        std::shared_ptr<Hook> find(size_t index) const;

        bool empty() const {
            return m_hooked.empty();
        }

    private:
        static size_t getVFuncCount(void** vtable);

        void*** m_class;
        void** m_origVtable;
        size_t m_vFuncCount;
        std::unique_ptr<void*[]> m_newVtable;

        std::shared_ptr<VHookCache> m_hookCache;

        std::unordered_map<size_t, std::shared_ptr<VHook>> m_hooked;
    };

    class VHookCache {
    public:
        std::shared_ptr<VHook> get(void* pFunc, const ConvFunc& convention);
        void clear();
        void removeUnused();

    private:
        std::unordered_map<void*, std::shared_ptr<VHook>> m_hooked;
    };
}