#include <dynohook/conventions/x64_systemV_call.h>

using namespace dyno;

x64SystemVcall::x64SystemVcall(std::vector<DataObject> arguments, DataObject returnType, size_t alignment) :
	ICallingConvention(std::move(arguments), returnType, alignment) {
	// don't force the register on the user

	RegisterType registers[] = { RDI, RSI, RDX, RCX, R8, R9 };

	for (size_t i = 0, j = 0, k = 0; i < m_arguments.size(); i++) {
		DataObject& arg = m_arguments[i];

		if (arg.reg == NONE) {
			// floating point arguments 1-8 ([XYZ]MM0 - [XYZ]MM7)
			if (k < 8 && (arg.isFlt() || arg.isVec()))
				arg.reg = SSEIndexToRegisterType(k++, arg.size);
			// integer/pointer arguments 1-6 (RDI, RSI, RDX, RCX, R8, R9)
			else if (j < 6)
				arg.reg = registers[j++];
			// static chain pointer (R10)
			// TODO: Suppose user should provide information about static chain pointer
		}
	}

	bool nonScalar = m_return.isFlt() || m_return.isVec();

	// integer return values up to 64 bits in size are stored in RAX while values up to 128 bit are stored in RAX and RDX.
	// floating-point return values are similarly stored in [XYZ]MM0 and [XYZ]MM1. TODO: We used [XYZ]MM0 by default, how we can detect another ?

	if (!nonScalar && m_return.size > 8)
		m_returnBuffer = malloc(m_return.size);
	else
		m_returnBuffer = nullptr;

	if (m_return.reg == NONE)
		m_return.reg = nonScalar ? SSEIndexToRegisterType(0, m_return.size) : RAX;

	init();
}

x64SystemVcall::~x64SystemVcall() {
	if (m_returnBuffer)
		free(m_returnBuffer);
}

regs_t x64SystemVcall::getRegisters() {
	regs_t registers;

	registers.push_back(RSP);

	// save all the custom calling convention registers as well.
	for (const auto& [type, reg, size] : m_arguments) {
		if (reg == NONE)
			continue;

		registers.push_back(reg);
	}

	// save return register as last
	if (m_returnBuffer) {
		registers.push_back(RAX);
		registers.push_back(RDX);
	} else {
		registers.push_back(m_return.reg);
	}

	return registers;
}

void** x64SystemVcall::getStackArgumentPtr(const Registers& registers) {
	return (void**) (registers[RSP].getValue<uintptr_t>() + 8);
}

void* x64SystemVcall::getArgumentPtr(size_t index, const Registers& registers) {
	if (index >= m_arguments.size())
		return nullptr;

	// check if this argument was passed in a register.
	RegisterType regType = m_arguments[index].reg;
	if (regType != NONE)
		return *registers[regType];

	size_t offset = 8;
	for (size_t i = 0; i < index; i++) {
		const auto& [type, reg, size] = m_arguments[i];
		if (reg == NONE)
			offset += size;
	}

	return (void*) (registers[RSP].getValue<uintptr_t>() + offset);
}

void x64SystemVcall::onArgumentPtrChanged(size_t index, const Registers& registers, void* argumentPtr) {
	DYNO_UNUSED(index);
	DYNO_UNUSED(registers);
	DYNO_UNUSED(argumentPtr);
}

void* x64SystemVcall::getReturnPtr(const Registers& registers) {
	if (m_returnBuffer) {
		// first half in rax, second half in rdx
		std::memcpy(m_returnBuffer, *registers.at(RAX, true), 8);
		std::memcpy((uint8_t*) m_returnBuffer + 8, *registers.at(RDX, true), 8);
		return m_returnBuffer;
	}

	return *registers.at(m_return.reg, true);
}

void x64SystemVcall::onReturnPtrChanged(const Registers& registers, void* returnPtr) {
	DYNO_UNUSED(returnPtr);
	if (m_returnBuffer) {
		// first half in rax, second half in rdx
		std::memcpy(*registers.at(RAX, true), m_returnBuffer, 8);
		std::memcpy(*registers.at(RDX, true), (uint8_t*) m_returnBuffer + 8, 8);
	}
}