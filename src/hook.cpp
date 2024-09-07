#include <dynohook/hook.h>
#include <dynohook/log.h>

using namespace dyno;

Hook::Hook(const ConvFunc& convention) : m_callingConvention{convention()}, m_registers{m_callingConvention->getRegisters()/*, Registers::ScratchList()*/} {
}

bool Hook::addCallback(CallbackType type, CallbackHandler handler) {
	if (!handler) {
		DYNO_LOG_WARN("Callback handler is null");
		return false;
	}

	std::vector<CallbackHandler>& callbacks = m_handlers[type];

	for (const CallbackHandler callback : callbacks) {
		if (callback == handler) {
			DYNO_LOG_WARN("Callback handler was already added");
			return false;
		}
	}

	callbacks.push_back(handler);
	return true;
}

bool Hook::removeCallback(CallbackType type, CallbackHandler handler) {
	if (!handler) {
		DYNO_LOG_WARN("Callback handler is null");
		return false;
	}

	auto it = m_handlers.find(type);
	if (it == m_handlers.end())
		return false;

	std::vector<CallbackHandler>& callbacks = it->second;

	for (size_t i = 0; i < callbacks.size(); i++) {
		if (callbacks[i] == handler) {
			callbacks.erase(callbacks.begin() + static_cast<ptrdiff_t>(i));
			if (callbacks.empty())
				m_handlers.erase(it);
			return true;
		}
	}

	DYNO_LOG_WARN("Callback handler not registered");
	return false;
}

bool Hook::isCallbackRegistered(CallbackType type, CallbackHandler handler) const {
	if (!handler) {
		DYNO_LOG_WARN("Callback handler is null");
		return false;
	}

	auto it = m_handlers.find(type);
	if (it == m_handlers.end())
		return false;

	const std::vector<CallbackHandler>& callbacks = it->second;

	for (const CallbackHandler callback : callbacks) {
		if (callback == handler)
			return true;
	}

	return false;
}

bool Hook::areCallbacksRegistered() const {
	auto it = m_handlers.find(CallbackType::Pre);
	if (it != m_handlers.end() && !it->second.empty())
		return true;

	it = m_handlers.find(CallbackType::Post);
	if (it != m_handlers.end() && !it->second.empty())
		return true;

	return false;
}

ReturnAction Hook::callbackHandler(CallbackType type) {
	DYNO_LOG_VERBOSE(type == CallbackType::Pre ? "callbackHandler::Pre" : "callbackHandler::Post");

	if (type == CallbackType::Post) {
		ReturnAction lastPreReturnAction = m_lastPreReturnAction.back();
		m_lastPreReturnAction.pop_back();
		if (lastPreReturnAction >= ReturnAction::Override)
			m_callingConvention->restoreReturnValue(m_registers);
		if (lastPreReturnAction < ReturnAction::Supercede)
			m_callingConvention->restoreCallArguments(m_registers);
	}

	ReturnAction returnAction = ReturnAction::Ignored;
	auto it = m_handlers.find(type);
	if (it == m_handlers.end()) {
		// still save the arguments for the post hook even if there
		// is no pre-handler registered.
		if (type == CallbackType::Pre) {
			m_lastPreReturnAction.push_back(returnAction);
			m_callingConvention->saveCallArguments(m_registers);
		}
		return returnAction;
	}

	const std::vector<CallbackHandler>& callbacks = it->second;

	for (const CallbackHandler callback : callbacks) {
		ReturnAction result = callback(type, *this);
		if (result > returnAction)
			returnAction = result;
	}

	if (type == CallbackType::Pre) {
		m_lastPreReturnAction.push_back(returnAction);
		if (returnAction >= ReturnAction::Override)
			m_callingConvention->saveReturnValue(m_registers);
		if (returnAction < ReturnAction::Supercede)
			m_callingConvention->saveCallArguments(m_registers);
	}

	return returnAction;
}

void* Hook::getReturnAddress(void* stackPtr) {
	DYNO_LOG_VERBOSE("getReturnAddress");

	auto it = m_retAddr.find(stackPtr);
	if (it == m_retAddr.end()) {
		DYNO_LOG_ERR("Failed to find return address of original function. Check the arguments and return type of your hook setup.");
		m_mutex.unlock();
		return nullptr;
	}

	std::vector<void*>& v = it->second;
	void* retAddr = v.back();
	v.pop_back();

	// clear the stack address from the cache now that we ran the last post hook.
	if (v.empty())
		m_retAddr.erase(it);

	m_mutex.unlock();

	return retAddr;
}

void Hook::setReturnAddress(void* retAddr, void* stackPtr) {
	m_mutex.lock();

	DYNO_LOG_VERBOSE("setReturnAddress");

#if DYNO_VERBOSE
	std::stringstream ss;
	ss << std::hex << std::setw(sizeof(void*) * 2) << std::setfill('0') << getAddress();
	DYNO_LOG_VERBOSE(ss.str());
#endif

	m_retAddr[stackPtr].push_back(retAddr);
}