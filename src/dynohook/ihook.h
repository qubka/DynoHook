#include "mem_accessor.h"

namespace dyno {
	class IHook : public MemAccessor {
	public:
		IHook() = default; // ctor
		IHook(IHook&& other) = default; //move
		IHook& operator=(IHook&& other) = default;//move assignment
		IHook(const IHook& other) = delete; //copy
		IHook& operator=(const IHook& other) = delete; //copy assignment
		virtual ~IHook() = default;

		virtual bool hook() = 0;
		virtual bool unhook() = 0;
		virtual bool rehook() {
			return true;
		}

		virtual bool setHooked(bool state) {
			if (m_hooked == state)
				return true;

			return state ? hook() : unhook();
		}

		virtual bool isHooked() {
			return m_hooked;
		}

		virtual HookType getType() const = 0;

		virtual void setDebug(bool state) {
			m_debugSet = state;
		}

	protected:
		bool m_debugSet{ false };
		bool m_hooked{ false };
	};
}