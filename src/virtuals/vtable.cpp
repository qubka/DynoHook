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

uint16_t VTable::getVFuncIndex(void* pFunc) {
	for (uint16_t i = 0; i < m_vFuncCount; ++i) {
		if (m_origVtable[i] == pFunc) 
			return i;
	}
	return kInvalidIndex;
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

std::shared_ptr<Hook> VTable::hook(void* pFunc, const ConvFunc& convention) {
	uint16_t index = getVFuncIndex(pFunc); 
	if (index == kInvalidIndex) {
		DYNO_LOG("Invalid virtual function: " + int_to_hex(pFunc), ErrorLevel::SEV);
		return nullptr;
	}
	
	return hook(index, convention);
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

bool VTable::unhook(void* pFunc) {
	uint16_t index = getVFuncIndex(pFunc); 
	if (index == kInvalidIndex) {
		DYNO_LOG("Invalid virtual function: " + int_to_hex(pFunc), ErrorLevel::SEV);
		return nullptr;
	}
	
	return unhook(index);
}

std::shared_ptr<Hook> VTable::find(uint16_t index) const {
	auto it = m_hooked.find(index);
	return it != m_hooked.end() ? it->second : nullptr;
}

std::shared_ptr<Hook> find(void* pFunc) const {
	uint16_t index = getVFuncIndex(pFunc); 
	if (index == kInvalidIndex) {
		DYNO_LOG("Invalid virtual function: " + int_to_hex(pFunc), ErrorLevel::SEV);
		return nullptr;
	}
	
	return find(index);
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