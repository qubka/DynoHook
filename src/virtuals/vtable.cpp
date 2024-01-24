#include <dynohook/virtuals/vtable.h>
#include <dynohook/mem_protector.h>

using namespace dyno;

VTable::VTable(void* pClass, std::shared_ptr<VHookCache> hookCache) : m_class{(void***)pClass}, m_hookCache{std::move(hookCache)} {
	MemProtector protector((uintptr_t)m_class, sizeof(void*), ProtFlag::R | ProtFlag::W, *this);

	m_origVtable = *m_class;
	m_vFuncCount = getVFuncCount(m_origVtable);
	m_newVtable = std::make_unique<void*[]>(m_vFuncCount);
	std::memcpy(m_newVtable.get(), m_origVtable, sizeof(void*) * m_vFuncCount);
	*m_class = m_newVtable.get();
}

VTable::~VTable() {
	MemProtector protector((uintptr_t)m_class, sizeof(void*), ProtFlag::R | ProtFlag::W, *this);

	*m_class = m_origVtable;

	//m_hookCache->cleanup();
}

int VTable::getVFuncCount(void** vtable) {
	int count = 0;
	while (true) {
		// if you have more than 512 vfuncs you have a problem
		if (!isValidPtr(vtable[++count]) || count > 512)
			break;
	}
	return count;
}

int VTable::getVTableIndex(void* pFunc) {
	static std::unordered_map<void*, int> cachedVTableIndexes;
	
	auto it = cachedVTableIndexes.find(pFunc);
	if (it != cachedVTableIndexes.end())
		return it->second;

	const size_t size = 12;

	MemProtector protector((uintptr_t)pFunc, size, ProtFlag::R, *this);

#if DYNO_PLATFORM_GCC_COMPATIBLE
	struct GCC_MemFunPtr {
		union {
			void* adrr;			// always even
			intptr_t vti_plus1; // vindex+1, always odd
		};
		intptr_t delta;
	};

	int vtindex;
	auto mfp_detail = (GCC_MemFunPtr*)&pFunc;
	if (mfp_detail->vti_plus1 & 1) {
		vtindex = (mfp_detail->vti_plus1 - 1) / sizeof(void*);
	} else {
		vtindex = -1;
	}
	
	cachedVTableIndexes.emplace(pFunc, vtindex);

	return vtindex;
#elif DYNO_PLATFORM_MSVC

	// https://github.com/alliedmodders/metamod-source/blob/aece7d5161178841aaf500b55a1e67647e9e38fb/core/sourcehook/sh_memfuncinfo.h

	// Check whether it's a virtual function call on x86
	
	// They look like this:a
	//		0:  8b 01                   mov    eax,DWORD PTR [ecx]
	//		2:  ff 60 04                jmp    DWORD PTR [eax+0x4]
	// ==OR==
	//		0:  8b 01                   mov    eax,DWORD PTR [ecx]
	//		2:  ff a0 18 03 00 00       jmp    DWORD PTR [eax+0x318]]

	// However, for vararg functions, they look like this:
	//		0:  8b 44 24 04             mov    eax,DWORD PTR [esp+0x4]
	//		4:  8b 00                   mov    eax,DWORD PTR [eax]
	//		6:  ff 60 08                jmp    DWORD PTR [eax+0x8]
	// ==OR==
	//		0:  8b 44 24 04             mov    eax,DWORD PTR [esp+0x4]
	//		4:  8b 00                   mov    eax,DWORD PTR [eax]
	//		6:  ff a0 18 03 00 00       jmp    DWORD PTR [eax+0x318]
	// With varargs, the this pointer is passed as if it was the first argument

	// On x64
	//		0:  48 8b 01                mov    rax,QWORD PTR [rcx]
	//		3:  ff 60 04                jmp    QWORD PTR [rax+0x4]
	// ==OR==
	//		0:  48 8b 01                mov    rax,QWORD PTR [rcx]
	//		3:  ff a0 18 03 00 00       jmp    QWORD PTR [rax+0x318]

	auto find_vtable_index = [&](uint8_t* addr) {
		std::unique_ptr<MemProtector> protector;

		if (*addr == 0xE9) {
			// May or may not be!
			// Check where it'd jump
			addr += 5 /*size of the instruction*/ + *(uint32_t*)(addr + 1);

			protector = std::make_unique<MemProtector>((uintptr_t)addr, size, ProtFlag::R, *this);
		}

		bool ok = false;
		
		if (addr[0] == 0x8B && addr[1] == 0x44 && addr[2] == 0x24 && addr[3] == 0x04 && addr[4] == 0x8B && addr[5] == 0x00) {
			addr += 6;
			ok = true;
		} else if (addr[0] == 0x8B && addr[1] == 0x01) {
			addr += 2;
			ok = true;
		} else if (addr[0] == 0x48 && addr[1] == 0x8B && addr[2] == 0x01) {
			addr += 3;
			ok = true;
		}
		
		if (!ok)
			return -1;

		constexpr int PtrSize = static_cast<int>(sizeof(void*));

		if (*addr++ == 0xFF) {
			if (*addr == 0x60)
				return *++addr / PtrSize;
			else if (*addr == 0xA0)
				return *((int*)++addr) / PtrSize;
			else if (*addr == 0x20)
				return 0;
			else
				return -1;
		}
		
		return -1;
	};

	int vtindex = find_vtable_index((uint8_t*)pFunc);
	cachedVTableIndexes.emplace(pFunc, vtindex);
	return vtindex;
#else
	#error "Compiler not support"
#endif
}

std::shared_ptr<Hook> VTable::hook(int index, const ConvFunc& convention) {
	if (index <= -1 || index >= m_vFuncCount) {
		DYNO_LOG("Invalid virtual function index: " + std::to_string(index), ErrorLevel::SEV);
		return nullptr;
	}

	auto it = m_hooked.find(int16_t(index));
	if (it != m_hooked.end())
		return it->second;

	auto vhook = m_hookCache->get(m_origVtable[index], convention);
	if (!vhook) {
		DYNO_LOG("Invalid virtual hook", ErrorLevel::SEV);
		return nullptr;
	}
	
	m_hooked.emplace(index, vhook);
	m_newVtable[index] = (void*) vhook->getBridge();
	return vhook;
}

bool VTable::unhook(int index) {
	if (index <= -1 || index >= m_vFuncCount) {
		DYNO_LOG("Invalid virtual function index: " + std::to_string(index), ErrorLevel::SEV);
		return false;
	}

	auto it = m_hooked.find(int16_t(index));
	if (it == m_hooked.end())
		return false;

	m_hooked.erase(it);
	m_newVtable[index] = m_origVtable[index];
	return true;
}

std::shared_ptr<Hook> VTable::find(int index) const {
	auto it = m_hooked.find(int16_t(index));
	return it != m_hooked.end() ? it->second : nullptr;
}

std::shared_ptr<VHook> VHookCache::get(void* pFunc, const ConvFunc &convention) {
	auto it = m_hooked.find(pFunc);
	if (it != m_hooked.end())
		return it->second;
	auto vhook = std::make_shared<VHook>((uintptr_t)pFunc, convention);
	if (!vhook->hook())
		return std::shared_ptr<VHook>(static_cast<VHook*>(nullptr));
	m_hooked.emplace(pFunc, vhook);
	return vhook;
}

void VHookCache::clear() {
	m_hooked.clear();
}

void VHookCache::cleanup() {
	if (m_hooked.empty())
		return;

	auto it = m_hooked.cbegin();
	while (it != m_hooked.cend()) {
		if (it->second.use_count() == 1) {
			it = m_hooked.erase(it);
		} else {
			++it;
		}
	}
}