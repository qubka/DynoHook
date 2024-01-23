#include <dynohook/conventions/x86_ms_fastcall.h>

using namespace dyno;

x86MsFastcall::x86MsFastcall(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
		x86MsStdcall(std::move(arguments), returnType, alignment) {

	// don't force the register on the user
	RegisterType registers[] = { ECX, EDX };

	for (size_t i = 0, j = 0; i < m_arguments.size(); i++) {
		DataObject& arg = m_arguments[i];

		// floating should be on stack
		if (arg.reg == NONE && !arg.isFlt() && j < 2)
			arg.reg = registers[j++];
	}

	init();
}