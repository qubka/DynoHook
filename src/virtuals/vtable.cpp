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

uint16_t VTable::getVFuncCount(void** vtable) {
	uint16_t count = 0;
	while (true) {
		// if you have more than 500 vfuncs you have a problem
		if (!isValidPtr(vtable[++count]) || count > 500)
			break;
	}
	return count;
}

uint16_t VTable::getVFuncIndex(void* mfp) const {
	static std::unordered_map<void*, uint16_t> cachedVTableIndexes;
	
	auto it = cachedVTableIndexes.find(mfp);
	if (it != cachedVTableIndexes.end())
		return it->second;


	// copy potentially remote memory to local buffer
	size_t read = 0;
	const size_t size = 14;
	auto buf = std::make_unique<uint8_t[]>(size);
	if (!accessor.safe_mem_read(mfp, (uintptr_t)buf.get(), size, read)) {
		cachedVTableIndexes.emplace(mfp, -1);
		return -1;
	}
	
#if DYNO_PLATFORM_GCC
	struct GCC_MemFunPtr {
		union {
			void* adrr;			// always even
			intptr_t vti_plus1; // vindex+1, always odd
		};
		intptr_t delta;
	};
	
	uint16_t vtindex;
	GCC_MemFunPtr* mfp_detail = (GCC_MemFunPtr*)&buf.get();
	if (mfp_detail->vti_plus1 & 1) {
		vtindex = (mfp_detail->vti_plus1 - 1) / sizeof(void*);
	} else {
		vtindex = -1;
	}
	
	cachedVTableIndexes.emplace(mfp, vtindex);
	
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
	
	// On x64
	//		0:  48 8b 01                mov    rax,QWORD PTR [rcx]
	//		3:  ff 60 04                jmp    QWORD PTR [rax+0x4]
	// ==OR==aa
	//		0:  48 8b 01                mov    rax,QWORD PTR [rcx]
	//		3:  ff a0 18 03 00 00       jmp    QWORD PTR [rax+0x318]
	
	
	// With varargs, the this pointer is passed as if it was the first argument

	auto find_table_index = [](uint8_t* addr) {
		if (*addr == 0xE9) {
			// May or may not be!
			// Check where it'd jump
			addr += 5 /*size of the instruction*/ + *(uintptr_t*)(addr + 1);
		}

		bool ok = false;
		
		if (addr[0] == 0x8B && addr[1] == 0x44 && addr[2] == 0x24 && addr[3] == 0x04 && addr[4] == 0x8B && addr[5] == 0x00) {
			addr += 6;
			ok = true;
		}
		else if (addr[0] == 0x8B && addr[1] == 0x01) {
			addr += 2;
			ok = true;
		}
		else if (addr[0] == 0x48 && addr[1] == 0x8B && addr[2] == 0x01) {
			addr += 3;
			ok = true;
		}
		
		if (!ok)
			return -1;

		if (*addr++ == 0xFF) {
			if (*addr == 0x60)
				return *++addr / sizeof(void*);
			else if (*addr == 0xA0) {
				return *((uintptr_t*)++addr) / sizeof(void*);
			else if (*addr == 0x20)
				return 0;
			else
				return -1;
		}
		
		return -1;
	};

	cachedVTableIndexes.emplace(mfp, find_table_index(buf.get()));
#else
	//#error "Compiler not support"
	cachedVTableIndexes.emplace(mfp, -1);
#endif
}

std::shared_ptr<Hook> VTable::hook(uint16_t index, const ConvFunc& convention) {
	if (index >= m_vFuncCount) {
		DYNO_LOG("Invalid virtual function index: " + std::to_string(index), ErrorLevel::SEV);
		return nullptr;
	}

	auto it = m_hooked.find(index);
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

bool VTable::unhook(uint16_t index) {
	if (index >= m_vFuncCount) {
		DYNO_LOG("Invalid virtual function index: " + std::to_string(index), ErrorLevel::SEV);
		return false;
	}

	auto it = m_hooked.find(index);
	if (it == m_hooked.end())
		return false;

	m_hooked.erase(it);
	m_newVtable[index] = m_origVtable[index];
	return true;
}

std::shared_ptr<Hook> VTable::find(uint16_t index) const {
	auto it = m_hooked.find(index);
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