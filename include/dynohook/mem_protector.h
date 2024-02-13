#pragma once

#include "prot.h"

namespace dyno {
	class MemAccessor;

	int TranslateProtection(ProtFlag flags);
	ProtFlag TranslateProtection(int prot);

	class MemProtector {
	public:
		MemProtector() = delete;
		MemProtector(uintptr_t address, std::size_t length, ProtFlag prot, MemAccessor& accessor, bool unsetOnDestroy = true);
		~MemProtector();
		
		ProtFlag originalProt() const {
			return m_origProtection;
		}

		bool isGood() const {
			return m_status;
		}

	private:
		MemAccessor& m_accessor;

		std::uintptr_t m_address;
		std::size_t m_length;
		bool m_status;
		bool m_unsetLater;
		
		ProtFlag m_origProtection{ ProtFlag::UNSET };
	};
}

//std::ostream& operator<<(std::ostream& os, dyno::ProtFlag v);