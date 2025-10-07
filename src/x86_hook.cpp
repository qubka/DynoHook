#include <dynohook/x86_hook.h>

using namespace dyno;
using namespace asmjit;
using namespace asmjit::x86;
using namespace std::string_literals;

x86Hook::x86Hook(const ConvFunc& convention) : Hook(convention), m_scratchRegisters(Registers::ScratchList()) {
}

bool x86Hook::createBridge() {
	assert(m_fnBridge == 0);

	CodeHolder code;
	code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpu_features());
	Assembler a(&code);

	Label override = a.new_label();

	// write a redirect to the post-hook code
	writeModifyReturnAddress(a);

	// call the pre-hook handler and jump to label override if true was returned
	writeCallHandler(a, CallbackType::Pre);
	a.cmp(al, ReturnAction::Supercede);

	// restore the previously saved registers, so any changes will be applied
	writeRestoreRegisters(a, false);

	// skip trampoline if equal
	a.je(override);

	// jump to the original address (trampoline)
	a.jmp(getAddress());

	// this code will be executed if a pre-hook returns Supercede
	a.bind(override);

	// finally, return to the caller
	// this will still call post hooks, but will skip the original function.
	size_t popSize = m_callingConvention->getPopSize();
	if (popSize > 0)
		a.ret(popSize);
	else
		a.ret();

	// generate code
	auto error = m_asmjit_rt.add(&m_fnBridge, &code);
	if (error != kErrorOk) {
		DYNO_LOG_ERR("AsmJit error: "s + DebugUtils::error_as_string(error));
		return false;
	}

	m_fnBridgeSize = code.code_size();

	return true;
}

bool x86Hook::createPostCallback() {
	assert(m_newRetAddr == 0);

	CodeHolder code;
	code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpu_features());
	Assembler a(&code);

	// gets pop size + return address
	size_t popSize = m_callingConvention->getPopSize() + sizeof(void*);

	// subtract the previously added bytes (stack size + return address), so
	// that we can access the arguments again
	a.sub(esp, popSize);

	// call the post-hook handler
	writeCallHandler(a, CallbackType::Post);

	// restore the previously saved registers, so any changes will be applied
	writeRestoreRegisters(a, true);

	// save scratch registers that are used by getReturnAddress
	writeSaveScratchRegisters(a);

	// get the original return address
	void* (DYNO_CDECL Hook::*getReturnAddress)(void*) = &x86Hook::getReturnAddress;

	// store stack pointer in eax
	a.mov(eax, esp);

	// subtract 4 bytes to preserve 16-byte stack alignment for Linux
	a.sub(esp, 4);
	a.push(eax);
	a.push(this);
	a.call((void*&) getReturnAddress); // +4 = 16 (aligned by 16 bytes)
	a.add(esp, 12);

	// save the original return address
	a.push(eax);

	// restore scratch registers
	writeRestoreScratchRegisters(a);

	// return to the original address
	// add the bytes again to the stack (stack size + return address), so we
	// don't corrupt the stack.
	a.ret(popSize);

	// generate code
	auto error = m_asmjit_rt.add(&m_newRetAddr, &code);
	if (error != kErrorOk) {
		DYNO_LOG_ERR("AsmJit error: "s + DebugUtils::error_as_string(error));
		return false;
	}

	m_newRetAddrSize = code.code_size();

	return true;
}

void x86Hook::writeModifyReturnAddress(Assembler& a) {
	/// https://en.wikipedia.org/wiki/X86_calling_conventions

	// save scratch registers that are used by setReturnAddress
	writeSaveScratchRegisters(a);

	// save the original return address by using the current sp as the key.
	// this should be unique until we have returned to the original caller.
	void (DYNO_CDECL Hook::*setReturnAddress)(void*, void*) = &x86Hook::setReturnAddress;

	// store the return address in eax
	a.mov(eax, dword_ptr(esp));

	a.push(esp);
	a.push(eax);
	a.push(this);
	a.call((void*&) setReturnAddress); // +4 = 16 (aligned by 16 bytes)
	a.add(esp, 12);

	// restore scratch registers
	writeRestoreScratchRegisters(a);

	// override the return address. This is a redirect to our post-hook code
	createPostCallback();
	a.mov(dword_ptr(esp), m_newRetAddr);
}

void x86Hook::writeCallHandler(Assembler& a, CallbackType type) const {
	ReturnAction (DYNO_CDECL Hook::*callbackHandler)(CallbackType) = &x86Hook::callbackHandler;

	// save the registers so that we can access them in our handlers
	writeSaveRegisters(a, type == CallbackType::Post);

	// call the global hook handler
	// subtract 4 bytes to preserve 16-byte stack alignment for Linux
	a.sub(esp, 4);
	a.push(type);
	a.push(this);
	a.call((void*&) callbackHandler); // +4 = 16 (aligned by 16 bytes)
	a.add(esp, 12);
}

int32_t x86Hook::writeSaveScratchRegisters(Assembler& a) const {
	for (const auto& reg : m_scratchRegisters) {
		writeRegToMem(a, reg, false);
	}
	return 0;
}

void x86Hook::writeRestoreScratchRegisters(Assembler& a) const {
	for (const auto& reg : m_scratchRegisters) {
		writeMemToReg(a, reg, false);
	}
}

void x86Hook::writeSaveRegisters(Assembler& a, bool post) const {
	for (const auto& reg : m_registers) {
		writeRegToMem(a, reg, post);
	}
}

void x86Hook::writeRestoreRegisters(Assembler& a, bool post) const {
	for (const auto& reg : m_registers) {
		writeMemToReg(a, reg, post);
	}
}

void x86Hook::writeRegToMem(Assembler& a, const Register& reg, bool post) const {
	uintptr_t addr = reg.getAddress<uintptr_t>();
	switch (reg) {
		// ========================================================================
		// >> 8-bit General purpose registers
		// ========================================================================
		case AL: a.mov(byte_ptr(addr), al); break;
		case CL: a.mov(byte_ptr(addr), cl); break;
		case DL: a.mov(byte_ptr(addr), dl); break;
		case BL: a.mov(byte_ptr(addr), bl); break;

		case AH: a.mov(byte_ptr(addr), ah); break;
		case CH: a.mov(byte_ptr(addr), ch); break;
		case DH: a.mov(byte_ptr(addr), dh); break;
		case BH: a.mov(byte_ptr(addr), bh); break;

		// ========================================================================
		// >> 16-bit General purpose registers
		// ========================================================================
		case AX: a.mov(word_ptr(addr), ax); break;
		case CX: a.mov(word_ptr(addr), cx); break;
		case DX: a.mov(word_ptr(addr), dx); break;
		case BX: a.mov(word_ptr(addr), bx); break;
		case SP: a.mov(word_ptr(addr), sp); break;
		case BP: a.mov(word_ptr(addr), bp); break;
		case SI: a.mov(word_ptr(addr), si); break;
		case DI: a.mov(word_ptr(addr), di); break;

		// ========================================================================
		// >> 32-bit General purpose registers
		// ========================================================================
		case EAX: a.mov(dword_ptr(addr), eax); break;
		case ECX: a.mov(dword_ptr(addr), ecx); break;
		case EDX: a.mov(dword_ptr(addr), edx); break;
		case EBX: a.mov(dword_ptr(addr), ebx); break;
		case ESP: a.mov(dword_ptr(addr), esp); break;
		case EBP: a.mov(dword_ptr(addr), ebp); break;
		case ESI: a.mov(dword_ptr(addr), esi); break;
		case EDI: a.mov(dword_ptr(addr), edi); break;

		// ========================================================================
		// >> 64-bit MM (MMX) registers
		// ========================================================================
		case MM0: a.movq(qword_ptr(addr), mm0); break;
		case MM1: a.movq(qword_ptr(addr), mm1); break;
		case MM2: a.movq(qword_ptr(addr), mm2); break;
		case MM3: a.movq(qword_ptr(addr), mm3); break;
		case MM4: a.movq(qword_ptr(addr), mm4); break;
		case MM5: a.movq(qword_ptr(addr), mm5); break;
		case MM6: a.movq(qword_ptr(addr), mm6); break;
		case MM7: a.movq(qword_ptr(addr), mm7); break;

		// ========================================================================
		// >> 128-bit XMM registers
		// ========================================================================
		case XMM0: a.movaps(dqword_ptr(addr), xmm0); break;
		case XMM1: a.movaps(dqword_ptr(addr), xmm1); break;
		case XMM2: a.movaps(dqword_ptr(addr), xmm2); break;
		case XMM3: a.movaps(dqword_ptr(addr), xmm3); break;
		case XMM4: a.movaps(dqword_ptr(addr), xmm4); break;
		case XMM5: a.movaps(dqword_ptr(addr), xmm5); break;
		case XMM6: a.movaps(dqword_ptr(addr), xmm6); break;
		case XMM7: a.movaps(dqword_ptr(addr), xmm7); break;

		// ========================================================================
		// >> 16-bit Segment registers
		// ========================================================================
		case CS: a.mov(word_ptr(addr), cs); break;
		case SS: a.mov(word_ptr(addr), ss); break;
		case DS: a.mov(word_ptr(addr), ds); break;
		case ES: a.mov(word_ptr(addr), es); break;
		case FS: a.mov(word_ptr(addr), fs); break;
		case GS: a.mov(word_ptr(addr), gs); break;

		// ========================================================================
		// >> 80-bit FPU registers
		// ========================================================================
		case ST0:
			// don't mess with the FPU stack in a pre-hook. The float return is returned in st0,
			// so only load it in a post hook to avoid writing back NaN.
			if (post) {
				switch (m_callingConvention->getReturn().size) {
					case SIZE_DWORD: a.fstp(dword_ptr(addr)); break;
					case SIZE_QWORD: a.fstp(qword_ptr(addr)); break;
					case SIZE_TWORD: a.fstp(tword_ptr(addr)); break;
				}
			}
			break;
		//case ST1: a.movl(tword_ptr(addr), st1); break;
		//case ST2: a.movl(tword_ptr(addr), st2); break;
		//case ST3: a.movl(tword_ptr(addr), st3); break;
		//case ST4: a.movl(tword_ptr(addr), st4); break;
		//case ST5: a.movl(tword_ptr(addr), st5); break;
		//case ST6: a.movl(tword_ptr(addr), st6); break;
		//case ST7: a.movl(tword_ptr(addr), st7); break;

		default: DYNO_LOG_WARN("Unsupported register.");
	}
}

void x86Hook::writeMemToReg(Assembler& a, const Register& reg, bool post) const {
	uintptr_t addr = reg.getAddress<uintptr_t>();
	switch (reg) {
		// ========================================================================
		// >> 8-bit General purpose registers
		// ========================================================================
		case AL: a.mov(al, byte_ptr(addr)); break;
		case CL: a.mov(cl, byte_ptr(addr)); break;
		case DL: a.mov(dl, byte_ptr(addr)); break;
		case BL: a.mov(bl, byte_ptr(addr)); break;

		case AH: a.mov(ah, byte_ptr(addr)); break;
		case CH: a.mov(ch, byte_ptr(addr)); break;
		case DH: a.mov(dh, byte_ptr(addr)); break;
		case BH: a.mov(bh, byte_ptr(addr)); break;

		// ========================================================================
		// >> 16-bit General purpose registers
		// ========================================================================
		case AX: a.mov(ax, word_ptr(addr)); break;
		case CX: a.mov(cx, word_ptr(addr)); break;
		case DX: a.mov(dx, word_ptr(addr)); break;
		case BX: a.mov(bx, word_ptr(addr)); break;
		case SP: a.mov(sp, word_ptr(addr)); break;
		case BP: a.mov(bp, word_ptr(addr)); break;
		case SI: a.mov(si, word_ptr(addr)); break;
		case DI: a.mov(di, word_ptr(addr)); break;

		// ========================================================================
		// >> 32-bit General purpose registers
		// ========================================================================
		case EAX: a.mov(eax, dword_ptr(addr)); break;
		case ECX: a.mov(ecx, dword_ptr(addr)); break;
		case EDX: a.mov(edx, dword_ptr(addr)); break;
		case EBX: a.mov(ebx, dword_ptr(addr)); break;
		case ESP: a.mov(esp, dword_ptr(addr)); break;
		case EBP: a.mov(ebp, dword_ptr(addr)); break;
		case ESI: a.mov(esi, dword_ptr(addr)); break;
		case EDI: a.mov(edi, dword_ptr(addr)); break;

		// ========================================================================
		// >> 64-bit MM (MMX) registers
		// ========================================================================
		case MM0: a.movq(mm0, qword_ptr(addr)); break;
		case MM1: a.movq(mm1, qword_ptr(addr)); break;
		case MM2: a.movq(mm2, qword_ptr(addr)); break;
		case MM3: a.movq(mm3, qword_ptr(addr)); break;
		case MM4: a.movq(mm4, qword_ptr(addr)); break;
		case MM5: a.movq(mm5, qword_ptr(addr)); break;
		case MM6: a.movq(mm6, qword_ptr(addr)); break;
		case MM7: a.movq(mm7, qword_ptr(addr)); break;

		// ========================================================================
		// >> 128-bit XMM registers
		// ========================================================================
		case XMM0: a.movaps(xmm0, dqword_ptr(addr)); break;
		case XMM1: a.movaps(xmm1, dqword_ptr(addr)); break;
		case XMM2: a.movaps(xmm2, dqword_ptr(addr)); break;
		case XMM3: a.movaps(xmm3, dqword_ptr(addr)); break;
		case XMM4: a.movaps(xmm4, dqword_ptr(addr)); break;
		case XMM5: a.movaps(xmm5, dqword_ptr(addr)); break;
		case XMM6: a.movaps(xmm6, dqword_ptr(addr)); break;
		case XMM7: a.movaps(xmm7, dqword_ptr(addr)); break;

		// ========================================================================
		// >> 16-bit Segment registers
		// ========================================================================
		case CS: a.mov(cs, word_ptr(addr)); break;
		case SS: a.mov(ss, word_ptr(addr)); break;
		case DS: a.mov(ds, word_ptr(addr)); break;
		case ES: a.mov(es, word_ptr(addr)); break;
		case FS: a.mov(fs, word_ptr(addr)); break;
		case GS: a.mov(gs, word_ptr(addr)); break;

		// ========================================================================
		// >> 80-bit FPU registers
		// ========================================================================
		case ST0:
			if (post) {
				// replace the top of the FPU stack.
				// copy st0 to st0 and pop -> just pop the FPU stack.
				a.fstp(st0);
				// push a value to the FPU stack.
				// TODO: Only write back when changed? Save full 80bits for that case.
				//	   Avoid truncation of the data if it's unchanged.
				switch (m_callingConvention->getReturn().size) {
					case SIZE_DWORD: a.fld(dword_ptr(addr)); break;
					case SIZE_QWORD: a.fld(qword_ptr(addr)); break;
					case SIZE_TWORD: a.fld(tword_ptr(addr)); break;
				}
			}
			break;
		//case ST1: a.movl(st1, tword_ptr(addr)); break;
		//case ST2: a.movl(st2, tword_ptr(addr)); break;
		//case ST3: a.movl(st3, tword_ptr(addr)); break;
		//case ST4: a.movl(st4, tword_ptr(addr)); break;
		//case ST5: a.movl(st5, tword_ptr(addr)); break;
		//case ST6: a.movl(st6, tword_ptr(addr)); break;
		//case ST7: a.movl(st7, tword_ptr(addr)); break;

		default: DYNO_LOG_WARN("Unsupported register.");
	}
}