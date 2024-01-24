#include <dynohook/manager.h>

using namespace dyno;

HookManager::HookManager() : m_cache{std::make_shared<VHookCache>()} {
}

std::shared_ptr<IHook> HookManager::hookDetour(void* pFunc, const ConvFunc& convention) {
	if (!pFunc)
		return nullptr;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_detours.find(pFunc);
	if (it != m_detours.end())
		return it->second;

	auto detour = std::make_shared<NatDetour>((uintptr_t)pFunc, convention);
	if (!detour->hook())
		return nullptr;

	m_detours.emplace(pFunc, detour);
	return detour;
}

std::shared_ptr<IHook> HookManager::hookVirtual(void* pClass, int index, const ConvFunc& convention) {
	if (!pClass)
		return nullptr;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_vtables.find(pClass);
	if (it != m_vtables.end())
		return it->second->hook(index, convention);

	auto vtable = std::make_unique<VTable>(pClass, m_cache);
	auto hook = vtable->hook(index, convention);
	if (hook) m_vtables.emplace(pClass, std::move(vtable));
	return hook;
}

std::shared_ptr<IHook> HookManager::hookVirtual(void* pClass, void* pFunc, const ConvFunc& convention) {
	if (!pClass)
		return nullptr;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_vtables.find(pClass);
	if (it != m_vtables.end()) {
		auto& table = it->second;
		int index = table->getVTableIndex(pFunc);
		if (index == -1)
			return nullptr;
		return table->hook(index, convention);
	}

	auto vtable = std::make_unique<VTable>(pClass, m_cache);

	int index = vtable->getVTableIndex(pFunc);
	if (index == -1)
		return nullptr;

	auto hook = vtable->hook(index, convention);
	if (hook) m_vtables.emplace(pClass, std::move(vtable));
	return hook;
	return nullptr;
}

bool HookManager::unhookDetour(void* pFunc) {
	if (!pFunc)
		return false;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_detours.find(pFunc);
	if (it != m_detours.end()) {
		m_detours.erase(it);
		return true;
	}

	return false;
}

bool HookManager::unhookVirtual(void* pClass, int index) {
	if (!pClass)
		return false;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_vtables.find(pClass);
	if (it != m_vtables.end()) {
		auto& table = it->second;
		if (table->unhook(index)) {
			if (table->empty())
				m_vtables.erase(it);
			return true;
		}

		return false;
	}

	return false;
}

bool HookManager::unhookVirtual(void* pClass, void* pFunc) {
	if (!pClass)
		return false;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_vtables.find(pClass);
	if (it != m_vtables.end()) {
		auto& table = it->second;

		int index = table->getVTableIndex(pFunc);
		if (index == -1)
			return false;

		if (table->unhook(index)) {
			if (table->empty())
				m_vtables.erase(it);
			return true;
		}

		return false;
	}

	return false;
}

std::shared_ptr<IHook> HookManager::findDetour(void* pFunc) const {
	auto it = m_detours.find(pFunc);
	return it != m_detours.end() ? it->second : nullptr;
}

std::shared_ptr<IHook> HookManager::findVirtual(void* pClass, int index) const {
	auto it = m_vtables.find(pClass);
	return it != m_vtables.end() ? it->second->find(index) : nullptr;
}

std::shared_ptr<IHook> HookManager::findVirtual(void* pClass, void* pFunc) const {
	auto it = m_vtables.find(pClass);
	if (it != m_vtables.end()){
		auto& table = it->second;
		int index = table->getVTableIndex(pFunc);
		if (index == -1)
			return nullptr;
		return table->find(index);
	}
	return nullptr;
}

void HookManager::unhookAll() {
	std::lock_guard<std::mutex> m_lock(m_mutex);

	m_cache->clear();
	m_detours.clear();
	m_vtables.clear();
}

void HookManager::unhookAllVirtual(void* pClass) {
	if (!pClass)
		return;

	std::lock_guard<std::mutex> m_lock(m_mutex);

	auto it = m_vtables.find(pClass);
	if (it != m_vtables.end())
		m_vtables.erase(it);
}

void HookManager::clearCache() {
	std::lock_guard<std::mutex> m_lock(m_mutex);

	m_cache->cleanup();
}

HookManager& HookManager::Get() {
	static HookManager s_manager;
	return s_manager;
}