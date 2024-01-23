#pragma once

#include <dynohook/virtuals/vhook.h>

namespace dyno {
	class VHookCache;

	class VTable final : public MemAccessor {
	public:
		VTable(void* pClass, std::shared_ptr<VHookCache> cache);
		~VTable() override;
		DYNO_NONCOPYABLE(VTable);

		std::shared_ptr<Hook> hook(uint16_t index, const ConvFunc& convention);
		std::shared_ptr<Hook> hook(void* pFunc, const ConvFunc& convention);
		
		bool unhook(uint16_t index);
		bool unhook(void* pFunc);

		std::shared_ptr<Hook> find(uint16_t index) const;
		std::shared_ptr<Hook> find(void* pFunc) const;

		bool empty() const {
			return m_hooked.empty();
		}

	private:
		static uint16_t getVFuncCount(void** vtable);
		static uint16_t getVFuncIndex(void* pFunc);
		
		constexpr uint16_t kInvalidIndex = std::numeric_limits<uint16_t>::max();

		void*** m_class;
		void** m_origVtable;
		uint16_t m_vFuncCount;
		std::unique_ptr<void*[]> m_newVtable;

		std::shared_ptr<VHookCache> m_hookCache;

		std::unordered_map<uint16_t, std::shared_ptr<VHook>> m_hooked;
	};

	class VHookCache {
	public:
		std::shared_ptr<VHook> get(void* pFunc, const ConvFunc& convention);
		void clear();
		void cleanup();

	private:
		std::unordered_map<void*, std::shared_ptr<VHook>> m_hooked;
	};
}