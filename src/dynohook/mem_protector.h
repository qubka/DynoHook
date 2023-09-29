#pragma once

#include "enums.h"

namespace dyno {
    class MemAccessor;

    int	TranslateProtection(ProtFlag flags);
    ProtFlag TranslateProtection(int prot);

	class MemProtector {
	public:
		MemProtector() = delete;
		MemProtector(uint64_t address, uint64_t length, ProtFlag prot, MemAccessor& accessor, bool unsetOnDestroy = true);
		~MemProtector();
		
		ProtFlag originalProt() {
			return m_origProtection;
		}

		bool isGood() {
			return status;
		}

	private:
		MemAccessor& m_accessor;

		uint64_t m_address;
		uint64_t m_length;
		bool status;
		bool unsetLater;
		
		ProtFlag m_origProtection{ ProtFlag::UNSET };
	};
}

//std::ostream& operator<<(std::ostream& os, dyno::ProtFlag v);