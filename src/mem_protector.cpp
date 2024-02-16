#include <dynohook/mem_protector.h>
#include <dynohook/mem_accessor.h>
#include <dynohook/os.h>

using namespace dyno;

MemProtector::MemProtector(uintptr_t address, size_t length, ProtFlag prot, MemAccessor& accessor, bool unsetOnDestroy) :
	m_accessor{accessor},
	m_address{address},
	m_length{length},
	m_status{false},
	m_unsetLater{unsetOnDestroy} {
	m_origProtection = m_accessor.mem_protect(address, length, prot, m_status);
}

MemProtector::~MemProtector() {
	if (m_origProtection == ProtFlag::UNSET || !m_unsetLater)
		return;

	m_accessor.mem_protect(m_address, m_length, m_origProtection, m_status);
}

namespace dyno {
	/*std::ostream& operator<<(std::ostream& os, ProtFlag flags) {
		if (flags == ProtFlag::UNSET) {
			os << "UNSET";
			return os;
		}

		if (flags & ProtFlag::X)
			os << "x";
		else
			os << "-";

		if (flags & ProtFlag::R)
			os << "r";
		else
			os << "-";

		if (flags & ProtFlag::W)
			os << "w";
		else
			os << "-";

		if (flags & ProtFlag::N)
			os << "n";
		else
			os << "-";

		if (flags & ProtFlag::P)
			os << " private";
		else if (flags & ProtFlag::S)
			os << " shared";
		return os;
	}*/

#if DYNO_PLATFORM_WINDOWS

	int TranslateProtection(ProtFlag flags) {
		int nativeFlag = 0;
		if (flags == ProtFlag::X)
			nativeFlag = PAGE_EXECUTE;

		if (flags == ProtFlag::R)
			nativeFlag = PAGE_READONLY;

		if (flags == ProtFlag::W || (flags == (ProtFlag::R | ProtFlag::W)))
			nativeFlag = PAGE_READWRITE;

		if ((flags & ProtFlag::X) && (flags & ProtFlag::R))
			nativeFlag = PAGE_EXECUTE_READ;

		if ((flags & ProtFlag::X) && (flags & ProtFlag::W))
			nativeFlag = PAGE_EXECUTE_READWRITE;

		if (flags & ProtFlag::N)
			nativeFlag = PAGE_NOACCESS;
		return nativeFlag;
	}

	ProtFlag TranslateProtection(int prot) {
		ProtFlag flags = ProtFlag::UNSET;
		switch (prot) {
			case PAGE_EXECUTE:
				flags = flags | ProtFlag::X;
				break;
			case PAGE_READONLY:
				flags = flags | ProtFlag::R;
				break;
			case PAGE_READWRITE:
				flags = flags | ProtFlag::W;
				flags = flags | ProtFlag::R;
				break;
			case PAGE_EXECUTE_READWRITE:
				flags = flags | ProtFlag::X;
				flags = flags | ProtFlag::R;
				flags = flags | ProtFlag::W;
				break;
			case PAGE_EXECUTE_READ:
				flags = flags | ProtFlag::X;
				flags = flags | ProtFlag::R;
				break;
			case PAGE_NOACCESS:
				flags = flags | ProtFlag::N;
				break;
		}
		return flags;
	}

#elif DYNO_PLATFORM_LINUX

	int TranslateProtection(ProtFlag flags) {
		int nativeFlag = PROT_NONE;
		if (flags & ProtFlag::X)
			nativeFlag |= PROT_EXEC;

		if (flags & ProtFlag::R)
			nativeFlag |= PROT_READ;

		if (flags & ProtFlag::W)
			nativeFlag |= PROT_WRITE;

		if (flags & ProtFlag::N)
			nativeFlag = PROT_NONE;

		return nativeFlag;
	}

	ProtFlag TranslateProtection(int prot) {
		ProtFlag flags = ProtFlag::UNSET;

		if (prot & PROT_EXEC)
			flags = flags | ProtFlag::X;

		if (prot & PROT_READ)
			flags = flags | ProtFlag::R;

		if (prot & PROT_WRITE)
			flags = flags | ProtFlag::W;

		if (prot == PROT_NONE)
			flags = flags | ProtFlag::N;

		return flags;
	}

#elif DYNO_PLATFORM_APPLE

	int TranslateProtection(ProtFlag flags) {
		int nativeFlag = VM_PROT_NONE;
		if (flags & ProtFlag::X)
			nativeFlag |= PROT_EXEC;

		if (flags & ProtFlag::R)
			nativeFlag |= PROT_READ;

		if (flags & ProtFlag::W)
			nativeFlag |= PROT_WRITE;

		if (flags & ProtFlag::N)
			nativeFlag = PROT_NONE;

		return nativeFlag;
	}

	ProtFlag TranslateProtection(int prot) {
		ProtFlag flags = ProtFlag::UNSET;

		if (prot & VM_PROT_EXECUTE)
			flags = flags | ProtFlag::X;

		if (prot & VM_PROT_READ)
			flags = flags | ProtFlag::R;

		if (prot & VM_PROT_WRITE)
			flags = flags | ProtFlag::W;

		if (prot == VM_PROT_NONE)
			flags = flags | ProtFlag::N;

		return flags;
	}

#endif

}