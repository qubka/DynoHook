#include <dynohook/disassembler.h>

#include <Zydis/Zydis.h>
#include <Zycore/Status.h>

using namespace dyno;

ZydisDisassembler::ZydisDisassembler(Mode mode) : m_decoder{new ZydisDecoder}, m_formatter{new ZydisFormatter}, m_mode{mode} {
	if (ZYAN_FAILED(ZydisDecoderInit(m_decoder,
									 (mode == Mode::x64) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
									 (mode == Mode::x64) ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32))) {
		throw std::runtime_error("Failed to initialize zydis decoder");
	}

	if (ZYAN_FAILED(ZydisFormatterInit(m_formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
		throw std::runtime_error("Failed to initialize zydis formatter");
	}

	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(m_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

ZydisDisassembler::~ZydisDisassembler() {
	if (m_decoder) {
		delete m_decoder;
		m_decoder = nullptr;
	}

	if (m_formatter) {
		delete m_formatter;
		m_formatter = nullptr;
	}
}

insts_t ZydisDisassembler::disassemble(
	uintptr_t firstInstruction,
	uintptr_t start,
	uintptr_t end,
	const MemAccessor& accessor
) {
	insts_t insVec;
//	m_branchMap.clear();

	size_t size = end - start;
	assert(size > 0);
	if (size <= 0) {
		return insVec;
	}

	// copy potentially remote memory to local buffer
	size_t read = 0;
	auto buf = std::make_unique<uint8_t[]>(size);
	if (!accessor.safe_mem_read(firstInstruction, (uintptr_t) buf.get(), size, read)) {
		return insVec;
	}
	ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];
	ZydisDecodedInstruction insInfo;
	size_t offset = 0;
	bool endHit = false;

	uint8_t* buffer;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(m_decoder, (char*) (buffer = (buf.get() + offset)), (ZyanUSize) (read - offset), &insInfo, decoded_operands))) {
		Instruction::Displacement displacement{0};
		displacement.Absolute = 0;

		uintptr_t address = start + offset;

		std::string opStr;
		if (!getOpStr(&insInfo, decoded_operands, address, &opStr)) {
			break;
		}

		Instruction inst(&accessor,
						 address,
						 displacement,
						 0,
						 false,
						 false,
						 std::vector<uint8_t>(buffer, buffer + insInfo.length),
						 ZydisMnemonicGetString(insInfo.mnemonic),
						 std::move(opStr),
						 m_mode);

		setDisplacementFields(inst, &insInfo, decoded_operands);
		if (endHit && !isPadBytes(inst)) {
			break;
		}

		for (auto i = 0; i < insInfo.operand_count; i++) {
			auto op = decoded_operands[i];
			if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type == ZYDIS_MEMOP_TYPE_MEM && op.mem.disp.size && op.mem.base == ZYDIS_REGISTER_NONE && op.mem.segment != ZYDIS_REGISTER_DS && inst.isIndirect()) {
				inst.setIndirect(false);
			}
		}

		insVec.push_back(inst);

		// searches instruction vector and updates references
		addToBranchMap(insVec, inst);
		if (isFuncEnd(inst, start == address)){
			endHit = true;
		}

		offset += insInfo.length;
	}

	return insVec;
}

bool ZydisDisassembler::getOpStr(ZydisDecodedInstruction* pInstruction, const ZydisDecodedOperand* decoded_operands, uintptr_t addr, std::string* pOpStrOut) {
	char buffer[256];
	if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(m_formatter, pInstruction, decoded_operands, pInstruction->operand_count, buffer, sizeof(buffer), (ZyanU64)addr, ZYAN_NULL))) {
		// remove mnemonic + space (op str is just the right hand side)
		std::string wholeInstStr(buffer);
		*pOpStrOut = wholeInstStr.erase(0, wholeInstStr.find(' ') + 1);
		return true;
	}
	return false;
}

void ZydisDisassembler::setDisplacementFields(Instruction& inst, const ZydisDecodedInstruction* zydisInst, const ZydisDecodedOperand* operands) {
	inst.setBranching(zydisInst->meta.branch_type != ZYDIS_BRANCH_TYPE_NONE);
	inst.setCalling(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL);

	for (auto i = 0; i < zydisInst->operand_count; i++) {
		const ZydisDecodedOperand* const operand = &operands[i];

		// skip implicit operands (r/w effects)
		if (operand->visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN ||
			operand->visibility == ZYDIS_OPERAND_VISIBILITY_INVALID) {
			continue;
		}

		switch (operand->type) {
			case ZYDIS_OPERAND_TYPE_REGISTER: {
				inst.setRegister(operand->reg.value);
				inst.addOperandType(Instruction::OperandType::Register);
				break;
			}
			case ZYDIS_OPERAND_TYPE_UNUSED:
				break;
			case ZYDIS_OPERAND_TYPE_MEMORY: { // Relative to RIP/EIP
				inst.addOperandType(Instruction::OperandType::Displacement);

				if (zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
					inst.setDisplacementOffset(zydisInst->raw.disp.offset);
					inst.setDisplacementSize((uint8_t)(zydisInst->raw.disp.size / 8));
					inst.setRelativeDisplacement(operand->mem.disp.value);
				}

				if ((zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x25) ||
					(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 2 && inst.getBytes().at(0) == 0xff && inst.getBytes().at(1) == 0x15) ||
					(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_CALL && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x15) ||
					(zydisInst->mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_JMP && inst.size() >= 3 && inst.getBytes().at(1) == 0xff && inst.getBytes().at(2) == 0x25)
					) {

					// is displacement set earlier already?
					if (!inst.hasDisplacement()) {
						// displacement is absolute on x86 mode
						inst.setDisplacementOffset(zydisInst->raw.disp.offset);
						inst.setAbsoluteDisplacement(zydisInst->raw.disp.value);
					}
					inst.setIndirect(true);
				}

				break;
			}
			case ZYDIS_OPERAND_TYPE_POINTER:
				break;
			case ZYDIS_OPERAND_TYPE_IMMEDIATE: {
				inst.addOperandType(Instruction::OperandType::Immediate);

				// is displacement set earlier already?
				if (!inst.hasDisplacement() && zydisInst->attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
					inst.setDisplacementOffset(zydisInst->raw.imm->offset);
					inst.setDisplacementSize((uint8_t)(zydisInst->raw.imm->size / 8));
					inst.setRelativeDisplacement(zydisInst->raw.imm->value.s);
					return;
				}

				inst.setImmediate(zydisInst->raw.imm->value.s);
				inst.setImmediateSize(zydisInst->raw.imm->size / 8);

				break;
			}
		}
	}
}

void ZydisDisassembler::addToBranchMap(insts_t& insVec, const Instruction& inst) {
	if (inst.isBranching()) {
		// search back, check if new instruction points to older ones (one to one)
		auto destInst = std::find_if(insVec.begin(), insVec.end(), [&](const Instruction& oldIns) {
			return oldIns.getAddress() == inst.getDestination();
		});

		if (destInst != insVec.end()) {
			updateBranchMap(destInst->getAddress(), inst);
		}
	}

	// search forward, check if old instructions now point to new one (many to one possible)
	for (const Instruction& oldInst : insVec) {
		if (oldInst.isBranching() && oldInst.hasDisplacement() && oldInst.getDestination() == inst.getAddress()) {
			updateBranchMap(inst.getAddress(), oldInst);
		}
	}
}

bool ZydisDisassembler::isFuncEnd(const Instruction& instruction, bool firstFunc) {
	auto& mnemonic = instruction.getMnemonic();
	auto& bytes = instruction.getBytes();
	return (instruction.size() == 1 && bytes[0] == 0xCC) ||
           (instruction.size() >= 2 && bytes[0] == 0xf3 && bytes[1] == 0xc3) || // rep ret
           (instruction.size() >= 2 && bytes[0] == 0xf2 && bytes[1] == 0xc3) || // bnd ret for Intel mpx
		   (mnemonic == "jmp" && !firstFunc) || // Jump to tranlslation
		   mnemonic == "ret" || mnemonic.find("iret") == 0;
}

bool ZydisDisassembler::isConditionalJump(const Instruction& instruction) {
	// http://unixwiz.net/techtips/x86-jumps.html
	if (instruction.size() < 1)
		return false;

	auto& bytes = instruction.getBytes();
	if (bytes[0] == 0x0F && instruction.size() > 1) {
		if (bytes[1] >= 0x80 && bytes[1] <= 0x8F)
			return true;
	}

	if (bytes[0] >= 0x70 && bytes[0] <= 0x7F)
		return true;

	if (bytes[0] == 0xE3)
		return true;

	return false;
}

typename branch_map_t::mapped_type& ZydisDisassembler::updateBranchMap(uintptr_t key, const Instruction& new_val) {
	auto it = m_branchMap.find(key);
	if (it != m_branchMap.end()) {
		it->second.push_back(new_val);
	} else {
		branch_map_t::mapped_type s;
		s.push_back(new_val);
		m_branchMap.emplace(key, s);
		return m_branchMap.at(key);
	}
	return it->second;
}



