#include <dynohook/detours/x86_detour.h>

using namespace dyno;

x86Detour::x86Detour(uintptr_t fnAddress, const ConvFunc& convention)
		: Detour(fnAddress, convention, getArchType()) {}

Mode x86Detour::getArchType() const {
	return Mode::x86;
}

uint8_t getJmpSize() {
	return 5;
}

bool x86Detour::hook() {
	DYNO_LOG("m_fnAddress: " + int_to_hex(m_fnAddress) + "\n", ErrorLevel::INFO);

	insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
	DYNO_LOG("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

	if (insts.empty()) {
		DYNO_LOG("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
		return false;
	}

	if (!followJmp(insts)) {
		DYNO_LOG("Prologue jmp resolution failed", ErrorLevel::SEV);
		return false;
	}

	// update given fn address to resolved one
	m_fnAddress = insts.front().getAddress();

	// --------------- END RECURSIVE JMP RESOLUTION ---------------------

	uintptr_t minProlSz = getJmpSize(); // min size of patches that may split instructions
	uintptr_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

	// find the prologue section we will overwrite with jmp + zero or more nops
	auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
	if (!prologueOpt) {
		DYNO_LOG("Function too small to hook safely!", ErrorLevel::SEV);
		return false;
	}

	assert(roundProlSz >= minProlSz);
	auto prologue = *prologueOpt;

	if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz)) {
		DYNO_LOG("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
		return false;
	}

	m_originalInsts = prologue;
	DYNO_LOG("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

	// copy all the prologue stuff to trampoline
	insts_t jmpTblOpt;
	if (!makeTrampoline(prologue, jmpTblOpt)) {
		return false;
	}

	// create the bridge function
	if (!createBridge()) {
		DYNO_LOG("Failed to create bridge", ErrorLevel::SEV);
		return false;
	}

	auto tramp_instructions = m_disasm.disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this);
	DYNO_LOG("Trampoline:\n" + instsToStr(tramp_instructions) + "\n\n", ErrorLevel::INFO);
	if (!jmpTblOpt.empty()) {
		DYNO_LOG("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n\n", ErrorLevel::INFO);
	}

	m_hookSize = (uint32_t) roundProlSz;
	m_nopProlOffset = (uint16_t) minProlSz;

	MemProtector prot(m_fnAddress, m_hookSize, ProtFlag::RWX, *this);

	m_hookInsts = makex86Jmp(m_fnAddress, m_fnBridge);
	DYNO_LOG("Hook instructions:\n" + instsToStr(m_hookInsts) + "\n", ErrorLevel::INFO);
	writeEncoding(m_hookInsts);

	// Nop the space between jmp and end of prologue
	assert(m_hookSize >= m_nopProlOffset);
	m_nopSize = (uint16_t) (m_hookSize - m_nopProlOffset);
	const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
	writeEncoding(nops);

	m_hooked = true;
	return true;
}

bool x86Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut) {
	assert(!prologue.empty());
	const uintptr_t prolStart = prologue.front().getAddress();
	const uint16_t prolSz = calcInstsSz(prologue);

	/**
	 * Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
	 * address will change each attempt, which changes delta, which changes the number of needed entries. So
	 * we just try until we hit that lucky number that works.
	 *
	 * The relocation could also because of data operations too. But that's specific to the function and can't
	 * work again on a retry (same function, duh). Return immediately in that case.
	 */
	uint8_t neededEntryCount = 5;
	insts_t instsNeedingEntry;
	insts_t instsNeedingReloc;
	insts_t instsNeedingTranslation;

	uint8_t retries = 0;
	do {
		if (retries++ > 4) {
			DYNO_LOG("Failed to calculate trampoline information", ErrorLevel::SEV);
			return false;
		}

		if (m_trampoline != 0) {
			delete[](uint8_t*) m_trampoline;
			neededEntryCount = (uint8_t) instsNeedingEntry.size();
		}

		// prol + jmp back to prol + N * jmpEntries
		m_trampolineSz = (uint16_t) (prolSz + getJmpSize() + getJmpSize() * neededEntryCount);
		m_trampoline = (uintptr_t) new uint8_t[m_trampolineSz];

		const intptr_t delta = 1 - prolStart;

		buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation);
	} while (instsNeedingEntry.size() > neededEntryCount);

	const intptr_t delta = (intptr_t) (m_trampoline - prolStart);
	MemProtector prot(m_trampoline, m_trampolineSz, ProtFlag::R | ProtFlag::W | ProtFlag::X, *this, false);

	// Insert jmp from trampoline -> prologue after overwritten section
	const uintptr_t jmpToProlAddr = m_trampoline + prolSz;
	const auto jmpToProl = makex86Jmp(jmpToProlAddr, prologue.front().getAddress() + prolSz);
	writeEncoding(jmpToProl);

	const auto makeJmpFn = [&](uintptr_t a, Instruction& inst) mutable {
		// move inst to trampoline and point instruction to entry
		auto oldDest = inst.getDestination();
		inst.setAddress(inst.getAddress() + delta);
		inst.setDestination(a);

		return makex86Jmp(a, oldDest);
	};

	const uintptr_t jmpTblStart = jmpToProlAddr + getJmpSize();
	trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc, instsNeedingEntry);
	return true;
}