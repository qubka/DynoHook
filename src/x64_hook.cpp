#include <dynohook/x64_hook.h>

using namespace dyno;
using namespace asmjit;
using namespace asmjit::x86;
using namespace std::string_literals;

x64Hook::x64Hook(const ConvFunc& convention) : Hook(convention) {

}

bool x64Hook::createBridge() {
	assert(m_fnBridge == 0);

	CodeHolder code;
	code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpuFeatures());
	Assembler a(&code);

	Label override = a.newLabel();

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
	const uintptr_t& address = getAddress();
	if (address) {
		a.jmp(address);
	} else {
		// make space for inserting near/far jump later
		std::array<uint8_t, 14> nops{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
		a.embedDataArray(TypeId::kUInt8, nops.data(), nops.size());
	}

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
	if (error) {
		DYNO_LOG_ERR("AsmJit error: "s + DebugUtils::errorAsString(error));
		return false;
	}

	m_fnBridgeSize = code.codeSize();

	return true;
}

bool x64Hook::createPostCallback() {
	assert(m_newRetAddr == 0);

	CodeHolder code;
	code.init(m_asmjit_rt.environment(), m_asmjit_rt.cpuFeatures());
	Assembler a(&code);

	// gets pop size + return address
	size_t popSize = m_callingConvention->getPopSize() + sizeof(void*);

	// subtract the previously added bytes (stack size + return address), so
	// that we can access the arguments again
	a.sub(rsp, popSize);

	// call the post-hook handler
	writeCallHandler(a, CallbackType::Post);

	// restore the previously saved registers, so any changes will be applied
	writeRestoreRegisters(a, true);

	// save scratch registers that are used by getReturnAddress
	int32_t pushed = writeSaveScratchRegisters(a);

	// get the original return address
	void* (DYNO_CDECL Hook::*getReturnAddress)(void*) = &x64Hook::getReturnAddress;

	// we saved scratch registers into stack, we might break 16-bytes alignment
	bool aligned = pushed % 16 == 0;
#if DYNO_PLATFORM_WINDOWS
	int reserved = aligned ? 40 : 32;
	a.lea(rdx, qword_ptr(rsp, pushed));
	a.mov(rcx, this);
	a.sub(rsp, reserved);
	a.call((void*&) getReturnAddress); // stack should be aligned by 16 bytes, call adds +8
	a.add(rsp, reserved);
#else // __systemV__
	int reserved = aligned ? 24 : 32;
	a.lea(rsi, qword_ptr(rsp, pushed));
	a.mov(rdi, this);
	a.sub(rsp, reserved);
	a.call((void*&) getReturnAddress); // stack should be aligned by 16 bytes, call adds +8
	a.add(rsp, reserved);
#endif
	// save the original return address
	a.push(rax);
	a.add(rsp, 8);

	// restore scratch registers
	writeRestoreScratchRegisters(a);

	// find previously stored return address and push it on top of stack
	a.push(rax);
	a.mov(rax, qword_ptr(rsp, -pushed));
	a.xchg(qword_ptr(rsp), rax);

	// return to the original address
	// add the bytes again to the stack (stack size + return address), so we
	// don't corrupt the stack.
	a.ret(popSize);

	// generate code
	auto error = m_asmjit_rt.add(&m_newRetAddr, &code);
	if (error) {
		DYNO_LOG_ERR("AsmJit error: "s + DebugUtils::errorAsString(error));
		return false;
	}

	m_newRetAddrSize = code.codeSize();

	return true;
}

void x64Hook::writeModifyReturnAddress(Assembler& a) {
	/// https://en.wikipedia.org/wiki/X86_calling_conventions

	// save scratch registers that are used by setReturnAddress
	int32_t pushed = writeSaveScratchRegisters(a);

	// save the original return address by using the current sp as the key.
	// this should be unique until we have returned to the original caller.
	void (DYNO_CDECL Hook::*setReturnAddress)(void*, void*) = &x64Hook::setReturnAddress;

	// we saved scratch registers into stack, we might break 16-bytes alignment
	bool aligned = pushed % 16 == 0;
#if DYNO_PLATFORM_WINDOWS
	int reserved = aligned ? 40 : 32;
	a.lea(r8, qword_ptr(rsp, pushed));
	a.mov(rdx, qword_ptr(rsp, pushed));
	a.mov(rcx, this);
	a.sub(rsp, reserved);
	a.call((void*&) setReturnAddress); // stack should be aligned by 16 bytes, call adds +8
	a.add(rsp, reserved);
#else // __systemV__
	int reserved = aligned ? 24 : 32;
	a.lea(rdx, qword_ptr(rsp, pushed));
	a.mov(rsi, qword_ptr(rsp, pushed));
	a.mov(rdi, this);
	a.sub(rsp, space;
	a.call((void*&) setReturnAddress); // stack should be aligned by 16 bytes, call adds +8
	a.add(rsp, reserved);
#endif

	// restore scratch registers
	writeRestoreScratchRegisters(a);

	// override the return address. This is a redirect to our post-hook code
	createPostCallback();

	// using rax because not possible to MOV r/m64, imm64
	a.mov(qword_ptr(rsp), rax);
	a.mov(rax, m_newRetAddr);
	a.xchg(qword_ptr(rsp), rax);
}

void x64Hook::writeCallHandler(Assembler& a, CallbackType type) const {
	ReturnAction (DYNO_CDECL Hook::*callbackHandler)(CallbackType) = &x64Hook::callbackHandler;

	// save the registers so that we can access them in our handlers
	writeSaveRegisters(a, type == CallbackType::Post);

	// call the global hook handler
#if DYNO_PLATFORM_WINDOWS
	a.mov(rdx, type);
	a.mov(rcx, this);
	a.sub(rsp, 40);
	a.call((void*&) callbackHandler); // +8 = 48 (aligned by 16 bytes)
	a.add(rsp, 40);
#else // __systemV__
	a.mov(rsi, type);
	a.mov(rdi, this);
	a.sub(rsp, 24);
	a.call((void*&) callbackHandler); // +8 = 32 (aligned by 16 bytes)
	a.add(rsp, 24);
#endif
}

int32_t x64Hook::writeSaveScratchRegisters(Assembler& a) const {
	int32_t size = 0;
	for (RegisterType reg : Registers::ScratchList()) {
		size += 8;
		switch (reg) {
			// ========================================================================
			// >> 8-bit General purpose registers
			// ========================================================================
			case AL: a.push(al); break;
			case CL: a.push(cl); break;
			case DL: a.push(dl); break;
			case BL: a.push(bl); break;

			case SPL: a.push(spl); break;
			case BPL: a.push(bpl); break;
			case SIL: a.push(sil); break;
			case DIL: a.push(dil); break;
			case R8B: a.push(r8b); break;
			case R9B: a.push(r9b); break;
			case R10B: a.push(r10b); break;
			case R11B: a.push(r11b); break;
			case R12B: a.push(r12b); break;
			case R13B: a.push(r13b); break;
			case R14B: a.push(r14b); break;
			case R15B: a.push(r15b); break;

			case AH: a.push(ah); break;
			case CH: a.push(ch); break;
			case DH: a.push(dh); break;
			case BH: a.push(bh); break;

			// ========================================================================
			// >> 16-bit General purpose registers
			// ========================================================================
			case AX: a.push(ax); break;
			case CX: a.push(cx); break;
			case DX: a.push(dx); break;
			case BX: a.push(bx); break;
			case SP: a.push(sp); break;
			case BP: a.push(bp); break;
			case SI: a.push(si); break;
			case DI: a.push(di); break;

			case R8W: a.push(r8w); break;
			case R9W: a.push(r9w); break;
			case R10W: a.push(r10w); break;
			case R11W: a.push(r11w); break;
			case R12W: a.push(r12w); break;
			case R13W: a.push(r13w); break;
			case R14W: a.push(r14w); break;
			case R15W: a.push(r15w); break;

			// ========================================================================
			// >> 32-bit General purpose registers
			// ========================================================================
			case EAX: a.push(eax); break;
			case ECX: a.push(ecx); break;
			case EDX: a.push(edx); break;
			case EBX: a.push(ebx); break;
			case ESP: a.push(esp); break;
			case EBP: a.push(ebp); break;
			case ESI: a.push(esi); break;
			case EDI: a.push(edi); break;

			case R8D: a.push(r8d); break;
			case R9D: a.push(r9d); break;
			case R10D: a.push(r10d); break;
			case R11D: a.push(r11d); break;
			case R12D: a.push(r12d); break;
			case R13D: a.push(r13d); break;
			case R14D: a.push(r14d); break;
			case R15D: a.push(r15d); break;

			// ========================================================================
			// >> 64-bit General purpose registers
			// ========================================================================
			case RAX: a.push(rax); break;
			case RCX: a.push(rcx); break;
			case RDX: a.push(rdx); break;
			case RBX: a.push(rbx); break;
			case RSP: a.push(rsp); break;
			case RBP: a.push(rbp); break;
			case RSI: a.push(rsi); break;
			case RDI: a.push(rdi); break;

			case R8: a.push(r8); break;
			case R9: a.push(r9); break;
			case R10: a.push(r10); break;
			case R11: a.push(r11); break;
			case R12: a.push(r12); break;
			case R13: a.push(r13); break;
			case R14: a.push(r14); break;
			case R15: a.push(r15); break;

			// ========================================================================
			// >> 64-bit MM (MMX) registers
			// ========================================================================
			case MM0: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm0); break;
			case MM1: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm1); break;
			case MM2: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm2); break;
			case MM3: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm3); break;
			case MM4: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm4); break;
			case MM5: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm5); break;
			case MM6: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm6); break;
			case MM7: a.sub(rsp, 8); a.movq(qword_ptr(rsp), mm7); break;

			// ========================================================================
			// >> 128-bit XMM registers
			// ========================================================================
			case XMM0: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm0); size += 8; break;
			case XMM1: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm1); size += 8; break;
			case XMM2: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm2); size += 8; break;
			case XMM3: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm3); size += 8; break;
			case XMM4: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm4); size += 8; break;
			case XMM5: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm5); size += 8; break;
			case XMM6: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm6); size += 8; break;
			case XMM7: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm7); size += 8; break;
			case XMM8: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm8); size += 8; break;
			case XMM9: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm9); size += 8; break;
			case XMM10: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm10); size += 8; break;
			case XMM11: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm11); size += 8; break;
			case XMM12: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm12); size += 8; break;
			case XMM13: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm13); size += 8; break;
			case XMM14: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm14); size += 8; break;
			case XMM15: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm15); size += 8; break;
#if DYNO_PLATFORM_AVX512
			case XMM16: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm16); size += 8; break;
			case XMM17: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm17); size += 8; break;
			case XMM18: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm18); size += 8; break;
			case XMM19: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm19); size += 8; break;
			case XMM20: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm20); size += 8; break;
			case XMM21: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm21); size += 8; break;
			case XMM22: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm22); size += 8; break;
			case XMM23: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm23); size += 8; break;
			case XMM24: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm24); size += 8; break;
			case XMM25: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm25); size += 8; break;
			case XMM26: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm26); size += 8; break;
			case XMM27: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm27); size += 8; break;
			case XMM28: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm28); size += 8; break;
			case XMM29: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm29); size += 8; break;
			case XMM30: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm30); size += 8; break;
			case XMM31: a.sub(rsp, 16); a.movaps(xmmword_ptr(rsp), xmm31); size += 8; break;
#endif // DYNO_PLATFORM_AVX512

			// ========================================================================
			// >> 256-bit YMM registers
			// ========================================================================
#if DYNO_PLATFORM_AVX
			case YMM0: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm0); size += 24; break;
			case YMM1: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm1); size += 24; break;
			case YMM2: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm2); size += 24; break;
			case YMM3: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm3); size += 24; break;
			case YMM4: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm4); size += 24; break;
			case YMM5: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm5); size += 24; break;
			case YMM6: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm6); size += 24; break;
			case YMM7: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm7); size += 24; break;
			case YMM8: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm8); size += 24; break;
			case YMM9: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm9); size += 24; break;
			case YMM10: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm10); size += 24; break;
			case YMM11: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm11); size += 24; break;
			case YMM12: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm12); size += 24; break;
			case YMM13: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm13); size += 24; break;
			case YMM14: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm14); size += 24; break;
			case YMM15: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm15); size += 24; break;
#if DYNO_PLATFORM_AVX512
			case YMM16: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm16); size += 24; break;
			case YMM17: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm17); size += 24; break;
			case YMM18: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm18); size += 24; break;
			case YMM19: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm19); size += 24; break;
			case YMM20: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm20); size += 24; break;
			case YMM21: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm21); size += 24; break;
			case YMM22: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm22); size += 24; break;
			case YMM23: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm23); size += 24; break;
			case YMM24: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm24); size += 24; break;
			case YMM25: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm25); size += 24; break;
			case YMM26: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm26); size += 24; break;
			case YMM27: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm27); size += 24; break;
			case YMM28: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm28); size += 24; break;
			case YMM29: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm29); size += 24; break;
			case YMM30: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm30); size += 24; break;
			case YMM31: a.sub(rsp, 32); a.vmovaps(ymmword_ptr(rsp), ymm31); size += 24; break;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_PLATFORM_AVX

			// ========================================================================
			// >> 512-bit ZMM registers
			// ========================================================================
#if DYNO_PLATFORM_AVX512
			case ZMM0: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm0); size += 56; break;
			case ZMM1: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm1); size += 56; break;
			case ZMM2: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm2); size += 56; break;
			case ZMM3: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm3); size += 56; break;
			case ZMM4: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm4); size += 56; break;
			case ZMM5: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm5); size += 56; break;
			case ZMM6: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm6); size += 56; break;
			case ZMM7: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm7); size += 56; break;
			case ZMM8: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm8); size += 56; break;
			case ZMM9: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm9); size += 56; break;
			case ZMM10: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm10); size += 56; break;
			case ZMM11: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm11); size += 56; break;
			case ZMM12: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm12); size += 56; break;
			case ZMM13: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm13); size += 56; break;
			case ZMM14: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm14); size += 56; break;
			case ZMM15: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm15); size += 56; break;
			case ZMM16: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm16); size += 56; break;
			case ZMM17: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm17); size += 56; break;
			case ZMM18: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm18); size += 56; break;
			case ZMM19: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm19); size += 56; break;
			case ZMM20: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm20); size += 56; break;
			case ZMM21: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm21); size += 56; break;
			case ZMM22: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm22); size += 56; break;
			case ZMM23: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm23); size += 56; break;
			case ZMM24: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm24); size += 56; break;
			case ZMM25: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm25); size += 56; break;
			case ZMM26: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm26); size += 56; break;
			case ZMM27: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm27); size += 56; break;
			case ZMM28: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm28); size += 56; break;
			case ZMM29: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm29); size += 56; break;
			case ZMM30: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm30); size += 56; break;
			case ZMM31: a.sub(rsp, 64); a.vmovaps(zmmword_ptr(rsp), zmm31); size += 56; break;
#endif // DYNO_PLATFORM_AVX512

			// ========================================================================
			// >> 16-bit Segment registers
			// ========================================================================
			case CS: a.push(cs); break;
			case SS: a.push(ss); break;
			case DS: a.push(ds); break;
			case ES: a.push(es); break;
			case FS: a.push(fs); break;
			case GS: a.push(gs); break;

			default: DYNO_LOG_WARN("Unsupported register.");
		}
	}
	return size;
}

void x64Hook::writeRestoreScratchRegisters(Assembler& a) const {
	auto& registers = Registers::ScratchList();

	for (size_t i = registers.size() - 1; i != -1; --i) {
		switch (registers[i]) {
			// ========================================================================
			// >> 8-bit General purpose registers
			// ========================================================================
			case AL: a.pop(al); break;
			case CL: a.pop(cl); break;
			case DL: a.pop(dl); break;
			case BL: a.pop(bl); break;

			case SPL: a.pop(spl); break;
			case BPL: a.pop(bpl); break;
			case SIL: a.pop(sil); break;
			case DIL: a.pop(dil); break;
			case R8B: a.pop(r8b); break;
			case R9B: a.pop(r9b); break;
			case R10B: a.pop(r10b); break;
			case R11B: a.pop(r11b); break;
			case R12B: a.pop(r12b); break;
			case R13B: a.pop(r13b); break;
			case R14B: a.pop(r14b); break;
			case R15B: a.pop(r15b); break;

			case AH: a.pop(ah); break;
			case CH: a.pop(ch); break;
			case DH: a.pop(dh); break;
			case BH: a.pop(bh); break;

			// ========================================================================
			// >> 16-bit General purpose registers
			// ========================================================================
			case AX: a.pop(ax); break;
			case CX: a.pop(cx); break;
			case DX: a.pop(dx); break;
			case BX: a.pop(bx); break;
			case SP: a.pop(sp); break;
			case BP: a.pop(bp); break;
			case SI: a.pop(si); break;
			case DI: a.pop(di); break;

			case R8W: a.pop(r8w); break;
			case R9W: a.pop(r9w); break;
			case R10W: a.pop(r10w); break;
			case R11W: a.pop(r11w); break;
			case R12W: a.pop(r12w); break;
			case R13W: a.pop(r13w); break;
			case R14W: a.pop(r14w); break;
			case R15W: a.pop(r15w); break;

			// ========================================================================
			// >> 32-bit General purpose registers
			// ========================================================================
			case EAX: a.pop(eax); break;
			case ECX: a.pop(ecx); break;
			case EDX: a.pop(edx); break;
			case EBX: a.pop(ebx); break;
			case ESP: a.pop(esp); break;
			case EBP: a.pop(ebp); break;
			case ESI: a.pop(esi); break;
			case EDI: a.pop(edi); break;

			case R8D: a.pop(r8d); break;
			case R9D: a.pop(r9d); break;
			case R10D: a.pop(r10d); break;
			case R11D: a.pop(r11d); break;
			case R12D: a.pop(r12d); break;
			case R13D: a.pop(r13d); break;
			case R14D: a.pop(r14d); break;
			case R15D: a.pop(r15d); break;

			// ========================================================================
			// >> 64-bit General purpose registers
			// ========================================================================
			case RAX: a.pop(rax); break;
			case RCX: a.pop(rcx); break;
			case RDX: a.pop(rdx); break;
			case RBX: a.pop(rbx); break;
			case RSP: a.pop(rsp); break;
			case RBP: a.pop(rbp); break;
			case RSI: a.pop(rsi); break;
			case RDI: a.pop(rdi); break;

			case R8: a.pop(r8); break;
			case R9: a.pop(r9); break;
			case R10: a.pop(r10); break;
			case R11: a.pop(r11); break;
			case R12: a.pop(r12); break;
			case R13: a.pop(r13); break;
			case R14: a.pop(r14); break;
			case R15: a.pop(r15); break;

			// ========================================================================
			// >> 64-bit MM (MMX) registers
			// ========================================================================
			case MM0: a.movq(mm0, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM1: a.movq(mm1, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM2: a.movq(mm2, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM3: a.movq(mm3, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM4: a.movq(mm4, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM5: a.movq(mm5, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM6: a.movq(mm6, qword_ptr(rsp)); a.add(rsp, 8); break;
			case MM7: a.movq(mm7, qword_ptr(rsp)); a.add(rsp, 8); break;

			// ========================================================================
			// >> 128-bit XMM registers
			// ========================================================================
			case XMM0: a.movaps(xmm0, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM1: a.movaps(xmm1, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM2: a.movaps(xmm2, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM3: a.movaps(xmm3, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM4: a.movaps(xmm4, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM5: a.movaps(xmm5, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM6: a.movaps(xmm6, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM7: a.movaps(xmm7, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM8: a.movaps(xmm8, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM9: a.movaps(xmm9, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM10: a.movaps(xmm10, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM11: a.movaps(xmm11, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM12: a.movaps(xmm12, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM13: a.movaps(xmm13, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM14: a.movaps(xmm14, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM15: a.movaps(xmm15, xmmword_ptr(rsp)); a.add(rsp, 16); break;
#if DYNO_PLATFORM_AVX512
			case XMM16: a.movaps(xmm16, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM17: a.movaps(xmm17, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM18: a.movaps(xmm18, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM19: a.movaps(xmm19, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM20: a.movaps(xmm20, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM21: a.movaps(xmm21, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM22: a.movaps(xmm22, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM23: a.movaps(xmm23, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM24: a.movaps(xmm24, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM25: a.movaps(xmm25, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM26: a.movaps(xmm26, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM27: a.movaps(xmm27, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM28: a.movaps(xmm28, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM29: a.movaps(xmm29, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM30: a.movaps(xmm30, xmmword_ptr(rsp)); a.add(rsp, 16); break;
			case XMM31: a.movaps(xmm31, xmmword_ptr(rsp)); a.add(rsp, 16); break;
#endif // DYNO_PLATFORM_AVX512

			// ========================================================================
			// >> 256-bit YMM registers
			// ========================================================================
#if DYNO_PLATFORM_AVX
			case YMM0: a.vmovaps(ymm0, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM1: a.vmovaps(ymm1, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM2: a.vmovaps(ymm2, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM3: a.vmovaps(ymm3, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM4: a.vmovaps(ymm4, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM5: a.vmovaps(ymm5, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM6: a.vmovaps(ymm6, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM7: a.vmovaps(ymm7, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM8: a.vmovaps(ymm8, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM9: a.vmovaps(ymm9, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM10: a.vmovaps(ymm10, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM11: a.vmovaps(ymm11, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM12: a.vmovaps(ymm12, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM13: a.vmovaps(ymm13, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM14: a.vmovaps(ymm14, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM15: a.vmovaps(ymm15, ymmword_ptr(rsp)); a.add(rsp, 32); break;
#if DYNO_PLATFORM_AVX512
			case YMM16: a.vmovaps(ymm16, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM17: a.vmovaps(ymm17, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM18: a.vmovaps(ymm18, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM19: a.vmovaps(ymm19, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM20: a.vmovaps(ymm20, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM21: a.vmovaps(ymm21, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM22: a.vmovaps(ymm22, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM23: a.vmovaps(ymm23, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM24: a.vmovaps(ymm24, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM25: a.vmovaps(ymm25, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM26: a.vmovaps(ymm26, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM27: a.vmovaps(ymm27, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM28: a.vmovaps(ymm28, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM29: a.vmovaps(ymm29, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM30: a.vmovaps(ymm30, ymmword_ptr(rsp)); a.add(rsp, 32); break;
			case YMM31: a.vmovaps(ymm31, ymmword_ptr(rsp)); a.add(rsp, 32); break;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_PLATFORM_AVX

			// ========================================================================
			// >> 512-bit ZMM registers
			// ========================================================================
#if DYNO_PLATFORM_AVX512
			case ZMM0: a.vmovaps(zmm0, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM1: a.vmovaps(zmm1, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM2: a.vmovaps(zmm2, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM3: a.vmovaps(zmm3, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM4: a.vmovaps(zmm4, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM5: a.vmovaps(zmm5, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM6: a.vmovaps(zmm6, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM7: a.vmovaps(zmm7, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM8: a.vmovaps(zmm8, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM9: a.vmovaps(zmm9, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM10: a.vmovaps(zmm10, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM11: a.vmovaps(zmm11, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM12: a.vmovaps(zmm12, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM13: a.vmovaps(zmm13, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM14: a.vmovaps(zmm14, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM15: a.vmovaps(zmm15, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM16: a.vmovaps(zmm16, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM17: a.vmovaps(zmm17, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM18: a.vmovaps(zmm18, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM19: a.vmovaps(zmm19, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM20: a.vmovaps(zmm20, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM21: a.vmovaps(zmm21, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM22: a.vmovaps(zmm22, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM23: a.vmovaps(zmm23, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM24: a.vmovaps(zmm24, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM25: a.vmovaps(zmm25, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM26: a.vmovaps(zmm26, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM27: a.vmovaps(zmm27, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM28: a.vmovaps(zmm28, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM29: a.vmovaps(zmm29, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM30: a.vmovaps(zmm30, zmmword_ptr(rsp)); a.add(rsp, 64); break;
			case ZMM31: a.vmovaps(zmm31, zmmword_ptr(rsp)); a.add(rsp, 64); break;
#endif // DYNO_PLATFORM_AVX512

			// ========================================================================
			// >> 16-bit Segment registers
			// ========================================================================
			case CS: a.pop(cs); break;
			case SS: a.pop(ss); break;
			case DS: a.pop(ds); break;
			case ES: a.pop(es); break;
			case FS: a.pop(fs); break;
			case GS: a.pop(gs); break;

			default: DYNO_LOG_WARN("Unsupported register.");
		}
	}
}

void x64Hook::writeSaveRegisters(Assembler& a, bool post) const {
	// save rax first, because we use it to save others

	for (const auto& reg : m_registers) {
		if (reg == RAX) {
			writeRegToMem(a, reg, post);
			break;
		}
	}

	for (const auto& reg : m_registers) {
		if (reg != RAX)
			writeRegToMem(a, reg, post);
	}
}

void x64Hook::writeRestoreRegisters(Assembler& a, bool post) const {
	// restore rax last, because we use it to restore others

	for (const auto& reg : m_registers) {
		if (reg != RAX)
			writeMemToReg(a, reg, post);
	}

	for (const auto& reg : m_registers) {
		if (reg == RAX) {
			writeMemToReg(a, reg, post);
			break;
		}
	}
}

void x64Hook::writeRegToMem(Assembler& a, const Register& reg, bool) const {
	/**
	 * The moffs8, moffs16, moffs32 and moffs64 operands specify a simple offset relative to the segment base,
	 * where 8, 16, 32 and 64 refer to the size of the data. The address-size attribute of the instruction determines the size of the offset, either 16, 32 or 64 bits.
	 * Supported only by RAX, EAX, AX, AL registers.
	 */
	uintptr_t addr = reg.getAddress<uintptr_t>();
	switch (reg) {
		// ========================================================================
		// >> 8-bit General purpose registers
		// ========================================================================
		case AL: a.mov(byte_ptr(addr), al); break;
		case CL: a.mov(rax, addr); a.mov(byte_ptr(rax), cl); break;
		case DL: a.mov(rax, addr); a.mov(byte_ptr(rax), dl); break;
		case BL: a.mov(rax, addr); a.mov(byte_ptr(rax), bl); break;

		case SPL: a.mov(rax, addr); a.mov(byte_ptr(rax), spl); break;
		case BPL: a.mov(rax, addr); a.mov(byte_ptr(rax), bpl); break;
		case SIL: a.mov(rax, addr); a.mov(byte_ptr(rax), sil); break;
		case DIL: a.mov(rax, addr); a.mov(byte_ptr(rax), dil); break;
		case R8B: a.mov(rax, addr); a.mov(byte_ptr(rax), r8b); break;
		case R9B: a.mov(rax, addr); a.mov(byte_ptr(rax), r9b); break;
		case R10B: a.mov(rax, addr); a.mov(byte_ptr(rax), r10b); break;
		case R11B: a.mov(rax, addr); a.mov(byte_ptr(rax), r11b); break;
		case R12B: a.mov(rax, addr); a.mov(byte_ptr(rax), r12b); break;
		case R13B: a.mov(rax, addr); a.mov(byte_ptr(rax), r13b); break;
		case R14B: a.mov(rax, addr); a.mov(byte_ptr(rax), r14b); break;
		case R15B: a.mov(rax, addr); a.mov(byte_ptr(rax), r15b); break;

		case AH: a.mov(rax, addr); a.mov(byte_ptr(rax), ah); break;
		case CH: a.mov(rax, addr); a.mov(byte_ptr(rax), ch); break;
		case DH: a.mov(rax, addr); a.mov(byte_ptr(rax), dh); break;
		case BH: a.mov(rax, addr); a.mov(byte_ptr(rax), bh); break;

		// ========================================================================
		// >> 16-bit General purpose registers
		// ========================================================================
		case AX: a.mov(word_ptr(addr), ax); break;
		case CX: a.mov(rax, addr); a.mov(word_ptr(rax), cx); break;
		case DX: a.mov(rax, addr); a.mov(word_ptr(rax), dx); break;
		case BX: a.mov(rax, addr); a.mov(word_ptr(rax), bx); break;
		case SP: a.mov(rax, addr); a.mov(word_ptr(rax), sp); break;
		case BP: a.mov(rax, addr); a.mov(word_ptr(rax), bp); break;
		case SI: a.mov(rax, addr); a.mov(word_ptr(rax), si); break;
		case DI: a.mov(rax, addr); a.mov(word_ptr(rax), di); break;

		case R8W: a.mov(rax, addr); a.mov(word_ptr(rax), r8w); break;
		case R9W: a.mov(rax, addr); a.mov(word_ptr(rax), r9w); break;
		case R10W: a.mov(rax, addr); a.mov(word_ptr(rax), r10w); break;
		case R11W: a.mov(rax, addr); a.mov(word_ptr(rax), r11w); break;
		case R12W: a.mov(rax, addr); a.mov(word_ptr(rax), r12w); break;
		case R13W: a.mov(rax, addr); a.mov(word_ptr(rax), r13w); break;
		case R14W: a.mov(rax, addr); a.mov(word_ptr(rax), r14w); break;
		case R15W: a.mov(rax, addr); a.mov(word_ptr(rax), r15w); break;

		// ========================================================================
		// >> 32-bit General purpose registers
		// ========================================================================
		case EAX: a.mov(dword_ptr(addr), eax); break;
		case ECX: a.mov(rax, addr); a.mov(dword_ptr(rax), ecx); break;
		case EDX: a.mov(rax, addr); a.mov(dword_ptr(rax), edx); break;
		case EBX: a.mov(rax, addr); a.mov(dword_ptr(rax), ebx); break;
		case ESP: a.mov(rax, addr); a.mov(dword_ptr(rax), esp); break;
		case EBP: a.mov(rax, addr); a.mov(dword_ptr(rax), ebp); break;
		case ESI: a.mov(rax, addr); a.mov(dword_ptr(rax), esi); break;
		case EDI: a.mov(rax, addr); a.mov(dword_ptr(rax), edi); break;

		case R8D: a.mov(rax, addr); a.mov(dword_ptr(rax), r8d); break;
		case R9D: a.mov(rax, addr); a.mov(dword_ptr(rax), r9d); break;
		case R10D: a.mov(rax, addr); a.mov(dword_ptr(rax), r10d); break;
		case R11D: a.mov(rax, addr); a.mov(dword_ptr(rax), r11d); break;
		case R12D: a.mov(rax, addr); a.mov(dword_ptr(rax), r12d); break;
		case R13D: a.mov(rax, addr); a.mov(dword_ptr(rax), r13d); break;
		case R14D: a.mov(rax, addr); a.mov(dword_ptr(rax), r14d); break;
		case R15D: a.mov(rax, addr); a.mov(dword_ptr(rax), r15d); break;

		// ========================================================================
		// >> 64-bit General purpose registers
		// ========================================================================
		case RAX: a.mov(qword_ptr(addr), rax); break;
		case RCX: a.mov(rax, addr); a.mov(qword_ptr(rax), rcx); break;
		case RDX: a.mov(rax, addr); a.mov(qword_ptr(rax), rdx); break;
		case RBX: a.mov(rax, addr); a.mov(qword_ptr(rax), rbx); break;
		case RSP: a.mov(rax, addr); a.mov(qword_ptr(rax), rsp); break;
		case RBP: a.mov(rax, addr); a.mov(qword_ptr(rax), rbp); break;
		case RSI: a.mov(rax, addr); a.mov(qword_ptr(rax), rsi); break;
		case RDI: a.mov(rax, addr); a.mov(qword_ptr(rax), rdi); break;

		case R8: a.mov(rax, addr); a.mov(qword_ptr(rax), r8); break;
		case R9: a.mov(rax, addr); a.mov(qword_ptr(rax), r9); break;
		case R10: a.mov(rax, addr); a.mov(qword_ptr(rax), r10); break;
		case R11: a.mov(rax, addr); a.mov(qword_ptr(rax), r11); break;
		case R12: a.mov(rax, addr); a.mov(qword_ptr(rax), r12); break;
		case R13: a.mov(rax, addr); a.mov(qword_ptr(rax), r13); break;
		case R14: a.mov(rax, addr); a.mov(qword_ptr(rax), r14); break;
		case R15: a.mov(rax, addr); a.mov(qword_ptr(rax), r15); break;

		// ========================================================================
		// >> 64-bit MM (MMX) registers
		// ========================================================================
		case MM0: a.mov(rax, addr); a.movq(qword_ptr(rax), mm0); break;
		case MM1: a.mov(rax, addr); a.movq(qword_ptr(rax), mm1); break;
		case MM2: a.mov(rax, addr); a.movq(qword_ptr(rax), mm2); break;
		case MM3: a.mov(rax, addr); a.movq(qword_ptr(rax), mm3); break;
		case MM4: a.mov(rax, addr); a.movq(qword_ptr(rax), mm4); break;
		case MM5: a.mov(rax, addr); a.movq(qword_ptr(rax), mm5); break;
		case MM6: a.mov(rax, addr); a.movq(qword_ptr(rax), mm6); break;
		case MM7: a.mov(rax, addr); a.movq(qword_ptr(rax), mm7); break;

		// ========================================================================
		// >> 128-bit XMM registers
		// ========================================================================
		case XMM0: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm0); break;
		case XMM1: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm1); break;
		case XMM2: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm2); break;
		case XMM3: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm3); break;
		case XMM4: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm4); break;
		case XMM5: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm5); break;
		case XMM6: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm6); break;
		case XMM7: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm7); break;
		case XMM8: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm8); break;
		case XMM9: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm9); break;
		case XMM10: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm10); break;
		case XMM11: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm11); break;
		case XMM12: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm12); break;
		case XMM13: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm13); break;
		case XMM14: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm14); break;
		case XMM15: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm15); break;
#if DYNO_PLATFORM_AVX512
		case XMM16: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm16); break;
		case XMM17: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm17); break;
		case XMM18: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm18); break;
		case XMM19: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm19); break;
		case XMM20: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm20); break;
		case XMM21: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm21); break;
		case XMM22: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm22); break;
		case XMM23: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm23); break;
		case XMM24: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm24); break;
		case XMM25: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm25); break;
		case XMM26: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm26); break;
		case XMM27: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm27); break;
		case XMM28: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm28); break;
		case XMM29: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm29); break;
		case XMM30: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm30); break;
		case XMM31: a.mov(rax, addr); a.movaps(xmmword_ptr(rax), xmm31); break;
#endif // DYNO_PLATFORM_AVX512

		// ========================================================================
		// >> 256-bit YMM registers
		// ========================================================================
#if DYNO_PLATFORM_AVX
		case YMM0: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm0); break;
		case YMM1: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm1); break;
		case YMM2: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm2); break;
		case YMM3: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm3); break;
		case YMM4: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm4); break;
		case YMM5: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm5); break;
		case YMM6: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm6); break;
		case YMM7: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm7); break;
		case YMM8: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm8); break;
		case YMM9: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm9); break;
		case YMM10: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm10); break;
		case YMM11: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm11); break;
		case YMM12: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm12); break;
		case YMM13: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm13); break;
		case YMM14: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm14); break;
		case YMM15: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm15); break;
#if DYNO_PLATFORM_AVX512
		case YMM16: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm16); break;
		case YMM17: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm17); break;
		case YMM18: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm18); break;
		case YMM19: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm19); break;
		case YMM20: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm20); break;
		case YMM21: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm21); break;
		case YMM22: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm22); break;
		case YMM23: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm23); break;
		case YMM24: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm24); break;
		case YMM25: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm25); break;
		case YMM26: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm26); break;
		case YMM27: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm27); break;
		case YMM28: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm28); break;
		case YMM29: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm29); break;
		case YMM30: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm30); break;
		case YMM31: a.mov(rax, addr); a.vmovaps(ymmword_ptr(rax), ymm31); break;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_PLATFORM_AVX

		// ========================================================================
		// >> 512-bit ZMM registers
		// ========================================================================
#if DYNO_PLATFORM_AVX512
		case ZMM0: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm0); break;
		case ZMM1: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm1); break;
		case ZMM2: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm2); break;
		case ZMM3: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm3); break;
		case ZMM4: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm4); break;
		case ZMM5: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm5); break;
		case ZMM6: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm6); break;
		case ZMM7: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm7); break;
		case ZMM8: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm8); break;
		case ZMM9: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm9); break;
		case ZMM10: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm10); break;
		case ZMM11: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm11); break;
		case ZMM12: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm12); break;
		case ZMM13: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm13); break;
		case ZMM14: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm14); break;
		case ZMM15: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm15); break;
		case ZMM16: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm16); break;
		case ZMM17: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm17); break;
		case ZMM18: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm18); break;
		case ZMM19: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm19); break;
		case ZMM20: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm20); break;
		case ZMM21: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm21); break;
		case ZMM22: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm22); break;
		case ZMM23: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm23); break;
		case ZMM24: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm24); break;
		case ZMM25: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm25); break;
		case ZMM26: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm26); break;
		case ZMM27: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm27); break;
		case ZMM28: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm28); break;
		case ZMM29: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm29); break;
		case ZMM30: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm30); break;
		case ZMM31: a.mov(rax, addr); a.vmovaps(zmmword_ptr(rax), zmm31); break;
#endif // DYNO_PLATFORM_AVX512

		// ========================================================================
		// >> 16-bit Segment registers
		// ========================================================================
		case CS: a.mov(rax, addr); a.mov(word_ptr(rax), cs); break;
		case SS: a.mov(rax, addr); a.mov(word_ptr(rax), ss); break;
		case DS: a.mov(rax, addr); a.mov(word_ptr(rax), ds); break;
		case ES: a.mov(rax, addr); a.mov(word_ptr(rax), es); break;
		case FS: a.mov(rax, addr); a.mov(word_ptr(rax), fs); break;
		case GS: a.mov(rax, addr); a.mov(word_ptr(rax), gs); break;

		default: DYNO_LOG_WARN("Unsupported register.");
	}
}

void x64Hook::writeMemToReg(Assembler& a, const Register& reg, bool) const {
	/**
	 * The moffs8, moffs16, moffs32 and moffs64 operands specify a simple offset relative to the segment base,
	 * where 8, 16, 32 and 64 refer to the size of the data. The address-size attribute of the instruction determines the size of the offset, either 16, 32 or 64 bits.
	 * Supported only by RAX, EAX, AX, AL registers.
	 */
	uintptr_t addr = reg.getAddress<uintptr_t>();
	switch (reg) {
		// ========================================================================
		// >> 8-bit General purpose registers
		// ========================================================================
		case AL: a.mov(al, byte_ptr(addr)); break;
		case CL: a.mov(rax, addr); a.mov(cl, byte_ptr(rax)); break;
		case DL: a.mov(rax, addr); a.mov(dl, byte_ptr(rax)); break;
		case BL: a.mov(rax, addr); a.mov(bl, byte_ptr(rax)); break;

		case SPL: a.mov(rax, addr); a.mov(spl, byte_ptr(rax)); break;
		case BPL: a.mov(rax, addr); a.mov(bpl, byte_ptr(rax)); break;
		case SIL: a.mov(rax, addr); a.mov(sil, byte_ptr(rax)); break;
		case DIL: a.mov(rax, addr); a.mov(dil, byte_ptr(rax)); break;
		case R8B: a.mov(rax, addr); a.mov(r8b, byte_ptr(rax)); break;
		case R9B: a.mov(rax, addr); a.mov(r9b, byte_ptr(rax)); break;
		case R10B: a.mov(rax, addr); a.mov(r10b, byte_ptr(rax)); break;
		case R11B: a.mov(rax, addr); a.mov(r11b, byte_ptr(rax)); break;
		case R12B: a.mov(rax, addr); a.mov(r12b, byte_ptr(rax)); break;
		case R13B: a.mov(rax, addr); a.mov(r13b, byte_ptr(rax)); break;
		case R14B: a.mov(rax, addr); a.mov(r14b, byte_ptr(rax)); break;
		case R15B: a.mov(rax, addr); a.mov(r15b, byte_ptr(rax)); break;

		case AH: a.mov(rax, addr); a.mov(ah, byte_ptr(rax)); break;
		case CH: a.mov(rax, addr); a.mov(ch, byte_ptr(rax)); break;
		case DH: a.mov(rax, addr); a.mov(dh, byte_ptr(rax)); break;
		case BH: a.mov(rax, addr); a.mov(bh, byte_ptr(rax)); break;

		// ========================================================================
		// >> 16-bit General purpose registers
		// ========================================================================
		case AX: a.mov(ax, word_ptr(addr)); break;
		case CX: a.mov(rax, addr); a.mov(cx, word_ptr(rax)); break;
		case DX: a.mov(rax, addr); a.mov(dx, word_ptr(rax)); break;
		case BX: a.mov(rax, addr); a.mov(bx, word_ptr(rax)); break;
		case SP: a.mov(rax, addr); a.mov(sp, word_ptr(rax)); break;
		case BP: a.mov(rax, addr); a.mov(bp, word_ptr(rax)); break;
		case SI: a.mov(rax, addr); a.mov(si, word_ptr(rax)); break;
		case DI: a.mov(rax, addr); a.mov(di, word_ptr(rax)); break;

		case R8W: a.mov(rax, addr); a.mov(r8w, word_ptr(rax)); break;
		case R9W: a.mov(rax, addr); a.mov(r9w, word_ptr(rax)); break;
		case R10W: a.mov(rax, addr); a.mov(r10w, word_ptr(rax)); break;
		case R11W: a.mov(rax, addr); a.mov(r11w, word_ptr(rax)); break;
		case R12W: a.mov(rax, addr); a.mov(r12w, word_ptr(rax)); break;
		case R13W: a.mov(rax, addr); a.mov(r13w, word_ptr(rax)); break;
		case R14W: a.mov(rax, addr); a.mov(r14w, word_ptr(rax)); break;
		case R15W: a.mov(rax, addr); a.mov(r15w, word_ptr(rax)); break;

		// ========================================================================
		// >> 32-bit General purpose registers
		// ========================================================================
		case EAX: a.mov(eax, dword_ptr(addr)); break;
		case ECX: a.mov(rax, addr); a.mov(ecx, dword_ptr(rax)); break;
		case EDX: a.mov(rax, addr); a.mov(edx, dword_ptr(rax)); break;
		case EBX: a.mov(rax, addr); a.mov(ebx, dword_ptr(rax)); break;
		case ESP: a.mov(rax, addr); a.mov(esp, dword_ptr(rax)); break;
		case EBP: a.mov(rax, addr); a.mov(ebp, dword_ptr(rax)); break;
		case ESI: a.mov(rax, addr); a.mov(esi, dword_ptr(rax)); break;
		case EDI: a.mov(rax, addr); a.mov(edi, dword_ptr(rax)); break;

		case R8D: a.mov(rax, addr); a.mov(r8d, dword_ptr(rax)); break;
		case R9D: a.mov(rax, addr); a.mov(r9d, dword_ptr(rax)); break;
		case R10D: a.mov(rax, addr); a.mov(r10d, dword_ptr(rax)); break;
		case R11D: a.mov(rax, addr); a.mov(r11d, dword_ptr(rax)); break;
		case R12D: a.mov(rax, addr); a.mov(r12d, dword_ptr(rax)); break;
		case R13D: a.mov(rax, addr); a.mov(r13d, dword_ptr(rax)); break;
		case R14D: a.mov(rax, addr); a.mov(r14d, dword_ptr(rax)); break;
		case R15D: a.mov(rax, addr); a.mov(r15d, dword_ptr(rax)); break;

		// ========================================================================
		// >> 64-bit General purpose registers
		// ========================================================================
		case RAX: a.mov(rax, qword_ptr(addr)); break;
		case RCX: a.mov(rax, addr); a.mov(rcx, qword_ptr(rax)); break;
		case RDX: a.mov(rax, addr); a.mov(rdx, qword_ptr(rax)); break;
		case RBX: a.mov(rax, addr); a.mov(rbx, qword_ptr(rax)); break;
		case RSP: a.mov(rax, addr); a.mov(rsp, qword_ptr(rax)); break;
		case RBP: a.mov(rax, addr); a.mov(rbp, qword_ptr(rax)); break;
		case RSI: a.mov(rax, addr); a.mov(rsi, qword_ptr(rax)); break;
		case RDI: a.mov(rax, addr); a.mov(rdi, qword_ptr(rax)); break;

		case R8: a.mov(rax, addr); a.mov(r8, qword_ptr(rax)); break;
		case R9: a.mov(rax, addr); a.mov(r9, qword_ptr(rax)); break;
		case R10: a.mov(rax, addr); a.mov(r10, qword_ptr(rax)); break;
		case R11: a.mov(rax, addr); a.mov(r11, qword_ptr(rax)); break;
		case R12: a.mov(rax, addr); a.mov(r12, qword_ptr(rax)); break;
		case R13: a.mov(rax, addr); a.mov(r13, qword_ptr(rax)); break;
		case R14: a.mov(rax, addr); a.mov(r14, qword_ptr(rax)); break;
		case R15: a.mov(rax, addr); a.mov(r15, qword_ptr(rax)); break;

		// ========================================================================
		// >> 64-bit MM (MMX) registers
		// ========================================================================
		case MM0: a.mov(rax, addr); a.movq(mm0, qword_ptr(rax)); break;
		case MM1: a.mov(rax, addr); a.movq(mm1, qword_ptr(rax)); break;
		case MM2: a.mov(rax, addr); a.movq(mm2, qword_ptr(rax)); break;
		case MM3: a.mov(rax, addr); a.movq(mm3, qword_ptr(rax)); break;
		case MM4: a.mov(rax, addr); a.movq(mm4, qword_ptr(rax)); break;
		case MM5: a.mov(rax, addr); a.movq(mm5, qword_ptr(rax)); break;
		case MM6: a.mov(rax, addr); a.movq(mm6, qword_ptr(rax)); break;
		case MM7: a.mov(rax, addr); a.movq(mm7, qword_ptr(rax)); break;

		// ========================================================================
		// >> 128-bit XMM registers
		// ========================================================================
		case XMM0: a.mov(rax, addr); a.movaps(xmm0, xmmword_ptr(rax)); break;
		case XMM1: a.mov(rax, addr); a.movaps(xmm1, xmmword_ptr(rax)); break;
		case XMM2: a.mov(rax, addr); a.movaps(xmm2, xmmword_ptr(rax)); break;
		case XMM3: a.mov(rax, addr); a.movaps(xmm3, xmmword_ptr(rax)); break;
		case XMM4: a.mov(rax, addr); a.movaps(xmm4, xmmword_ptr(rax)); break;
		case XMM5: a.mov(rax, addr); a.movaps(xmm5, xmmword_ptr(rax)); break;
		case XMM6: a.mov(rax, addr); a.movaps(xmm6, xmmword_ptr(rax)); break;
		case XMM7: a.mov(rax, addr); a.movaps(xmm7, xmmword_ptr(rax)); break;
		case XMM8: a.mov(rax, addr); a.movaps(xmm8, xmmword_ptr(rax)); break;
		case XMM9: a.mov(rax, addr); a.movaps(xmm9, xmmword_ptr(rax)); break;
		case XMM10: a.mov(rax, addr); a.movaps(xmm10, xmmword_ptr(rax)); break;
		case XMM11: a.mov(rax, addr); a.movaps(xmm11, xmmword_ptr(rax)); break;
		case XMM12: a.mov(rax, addr); a.movaps(xmm12, xmmword_ptr(rax)); break;
		case XMM13: a.mov(rax, addr); a.movaps(xmm13, xmmword_ptr(rax)); break;
		case XMM14: a.mov(rax, addr); a.movaps(xmm14, xmmword_ptr(rax)); break;
		case XMM15: a.mov(rax, addr); a.movaps(xmm15, xmmword_ptr(rax)); break;
#if DYNO_PLATFORM_AVX512
		case XMM16: a.mov(rax, addr); a.movaps(xmm16, xmmword_ptr(rax)); break;
		case XMM17: a.mov(rax, addr); a.movaps(xmm17, xmmword_ptr(rax)); break;
		case XMM18: a.mov(rax, addr); a.movaps(xmm18, xmmword_ptr(rax)); break;
		case XMM19: a.mov(rax, addr); a.movaps(xmm19, xmmword_ptr(rax)); break;
		case XMM20: a.mov(rax, addr); a.movaps(xmm20, xmmword_ptr(rax)); break;
		case XMM21: a.mov(rax, addr); a.movaps(xmm21, xmmword_ptr(rax)); break;
		case XMM22: a.mov(rax, addr); a.movaps(xmm22, xmmword_ptr(rax)); break;
		case XMM23: a.mov(rax, addr); a.movaps(xmm23, xmmword_ptr(rax)); break;
		case XMM24: a.mov(rax, addr); a.movaps(xmm24, xmmword_ptr(rax)); break;
		case XMM25: a.mov(rax, addr); a.movaps(xmm25, xmmword_ptr(rax)); break;
		case XMM26: a.mov(rax, addr); a.movaps(xmm26, xmmword_ptr(rax)); break;
		case XMM27: a.mov(rax, addr); a.movaps(xmm27, xmmword_ptr(rax)); break;
		case XMM28: a.mov(rax, addr); a.movaps(xmm28, xmmword_ptr(rax)); break;
		case XMM29: a.mov(rax, addr); a.movaps(xmm29, xmmword_ptr(rax)); break;
		case XMM30: a.mov(rax, addr); a.movaps(xmm30, xmmword_ptr(rax)); break;
		case XMM31: a.mov(rax, addr); a.movaps(xmm31, xmmword_ptr(rax)); break;
#endif // DYNO_PLATFORM_AVX512

		// ========================================================================
		// >> 256-bit YMM registers
		// ========================================================================
#if DYNO_PLATFORM_AVX
		case YMM0: a.mov(rax, addr); a.vmovaps(ymm0, ymmword_ptr(rax)); break;
		case YMM1: a.mov(rax, addr); a.vmovaps(ymm1, ymmword_ptr(rax)); break;
		case YMM2: a.mov(rax, addr); a.vmovaps(ymm2, ymmword_ptr(rax)); break;
		case YMM3: a.mov(rax, addr); a.vmovaps(ymm3, ymmword_ptr(rax)); break;
		case YMM4: a.mov(rax, addr); a.vmovaps(ymm4, ymmword_ptr(rax)); break;
		case YMM5: a.mov(rax, addr); a.vmovaps(ymm5, ymmword_ptr(rax)); break;
		case YMM6: a.mov(rax, addr); a.vmovaps(ymm6, ymmword_ptr(rax)); break;
		case YMM7: a.mov(rax, addr); a.vmovaps(ymm7, ymmword_ptr(rax)); break;
		case YMM8: a.mov(rax, addr); a.vmovaps(ymm8, ymmword_ptr(rax)); break;
		case YMM9: a.mov(rax, addr); a.vmovaps(ymm9, ymmword_ptr(rax)); break;
		case YMM10: a.mov(rax, addr); a.vmovaps(ymm10, ymmword_ptr(rax)); break;
		case YMM11: a.mov(rax, addr); a.vmovaps(ymm11, ymmword_ptr(rax)); break;
		case YMM12: a.mov(rax, addr); a.vmovaps(ymm12, ymmword_ptr(rax)); break;
		case YMM13: a.mov(rax, addr); a.vmovaps(ymm13, ymmword_ptr(rax)); break;
		case YMM14: a.mov(rax, addr); a.vmovaps(ymm14, ymmword_ptr(rax)); break;
		case YMM15: a.mov(rax, addr); a.vmovaps(ymm15, ymmword_ptr(rax)); break;
#if DYNO_PLATFORM_AVX512
		case YMM16: a.mov(rax, addr); a.vmovaps(ymm16, ymmword_ptr(rax)); break;
		case YMM17: a.mov(rax, addr); a.vmovaps(ymm17, ymmword_ptr(rax)); break;
		case YMM18: a.mov(rax, addr); a.vmovaps(ymm18, ymmword_ptr(rax)); break;
		case YMM19: a.mov(rax, addr); a.vmovaps(ymm19, ymmword_ptr(rax)); break;
		case YMM20: a.mov(rax, addr); a.vmovaps(ymm20, ymmword_ptr(rax)); break;
		case YMM21: a.mov(rax, addr); a.vmovaps(ymm21, ymmword_ptr(rax)); break;
		case YMM22: a.mov(rax, addr); a.vmovaps(ymm22, ymmword_ptr(rax)); break;
		case YMM23: a.mov(rax, addr); a.vmovaps(ymm23, ymmword_ptr(rax)); break;
		case YMM24: a.mov(rax, addr); a.vmovaps(ymm24, ymmword_ptr(rax)); break;
		case YMM25: a.mov(rax, addr); a.vmovaps(ymm25, ymmword_ptr(rax)); break;
		case YMM26: a.mov(rax, addr); a.vmovaps(ymm26, ymmword_ptr(rax)); break;
		case YMM27: a.mov(rax, addr); a.vmovaps(ymm27, ymmword_ptr(rax)); break;
		case YMM28: a.mov(rax, addr); a.vmovaps(ymm28, ymmword_ptr(rax)); break;
		case YMM29: a.mov(rax, addr); a.vmovaps(ymm29, ymmword_ptr(rax)); break;
		case YMM30: a.mov(rax, addr); a.vmovaps(ymm30, ymmword_ptr(rax)); break;
		case YMM31: a.mov(rax, addr); a.vmovaps(ymm31, ymmword_ptr(rax)); break;
#endif // DYNO_PLATFORM_AVX512
#endif // DYNO_PLATFORM_AVX

		// ========================================================================
		// >> 512-bit ZMM registers
		// ========================================================================
#if DYNO_PLATFORM_AVX512
		case ZMM0: a.mov(rax, addr); a.vmovaps(zmm0, zmmword_ptr(rax)); break;
		case ZMM1: a.mov(rax, addr); a.vmovaps(zmm1, zmmword_ptr(rax)); break;
		case ZMM2: a.mov(rax, addr); a.vmovaps(zmm2, zmmword_ptr(rax)); break;
		case ZMM3: a.mov(rax, addr); a.vmovaps(zmm3, zmmword_ptr(rax)); break;
		case ZMM4: a.mov(rax, addr); a.vmovaps(zmm4, zmmword_ptr(rax)); break;
		case ZMM5: a.mov(rax, addr); a.vmovaps(zmm5, zmmword_ptr(rax)); break;
		case ZMM6: a.mov(rax, addr); a.vmovaps(zmm6, zmmword_ptr(rax)); break;
		case ZMM7: a.mov(rax, addr); a.vmovaps(zmm7, zmmword_ptr(rax)); break;
		case ZMM8: a.mov(rax, addr); a.vmovaps(zmm8, zmmword_ptr(rax)); break;
		case ZMM9: a.mov(rax, addr); a.vmovaps(zmm9, zmmword_ptr(rax)); break;
		case ZMM10: a.mov(rax, addr); a.vmovaps(zmm10, zmmword_ptr(rax)); break;
		case ZMM11: a.mov(rax, addr); a.vmovaps(zmm11, zmmword_ptr(rax)); break;
		case ZMM12: a.mov(rax, addr); a.vmovaps(zmm12, zmmword_ptr(rax)); break;
		case ZMM13: a.mov(rax, addr); a.vmovaps(zmm13, zmmword_ptr(rax)); break;
		case ZMM14: a.mov(rax, addr); a.vmovaps(zmm14, zmmword_ptr(rax)); break;
		case ZMM15: a.mov(rax, addr); a.vmovaps(zmm15, zmmword_ptr(rax)); break;
		case ZMM16: a.mov(rax, addr); a.vmovaps(zmm16, zmmword_ptr(rax)); break;
		case ZMM17: a.mov(rax, addr); a.vmovaps(zmm17, zmmword_ptr(rax)); break;
		case ZMM18: a.mov(rax, addr); a.vmovaps(zmm18, zmmword_ptr(rax)); break;
		case ZMM19: a.mov(rax, addr); a.vmovaps(zmm19, zmmword_ptr(rax)); break;
		case ZMM20: a.mov(rax, addr); a.vmovaps(zmm20, zmmword_ptr(rax)); break;
		case ZMM21: a.mov(rax, addr); a.vmovaps(zmm21, zmmword_ptr(rax)); break;
		case ZMM22: a.mov(rax, addr); a.vmovaps(zmm22, zmmword_ptr(rax)); break;
		case ZMM23: a.mov(rax, addr); a.vmovaps(zmm23, zmmword_ptr(rax)); break;
		case ZMM24: a.mov(rax, addr); a.vmovaps(zmm24, zmmword_ptr(rax)); break;
		case ZMM25: a.mov(rax, addr); a.vmovaps(zmm25, zmmword_ptr(rax)); break;
		case ZMM26: a.mov(rax, addr); a.vmovaps(zmm26, zmmword_ptr(rax)); break;
		case ZMM27: a.mov(rax, addr); a.vmovaps(zmm27, zmmword_ptr(rax)); break;
		case ZMM28: a.mov(rax, addr); a.vmovaps(zmm28, zmmword_ptr(rax)); break;
		case ZMM29: a.mov(rax, addr); a.vmovaps(zmm29, zmmword_ptr(rax)); break;
		case ZMM30: a.mov(rax, addr); a.vmovaps(zmm30, zmmword_ptr(rax)); break;
		case ZMM31: a.mov(rax, addr); a.vmovaps(zmm31, zmmword_ptr(rax)); break;
#endif // DYNO_PLATFORM_AVX512

		// ========================================================================
		// >> 16-bit Segment registers
		// ========================================================================
		case CS: a.mov(rax, addr); a.mov(cs, word_ptr(rax)); break;
		case SS: a.mov(rax, addr); a.mov(ss, word_ptr(rax)); break;
		case DS: a.mov(rax, addr); a.mov(ds, word_ptr(rax)); break;
		case ES: a.mov(rax, addr); a.mov(es, word_ptr(rax)); break;
		case FS: a.mov(rax, addr); a.mov(fs, word_ptr(rax)); break;
		case GS: a.mov(rax, addr); a.mov(gs, word_ptr(rax)); break;

		default: DYNO_LOG_WARN("Unsupported register.");
	}
}
