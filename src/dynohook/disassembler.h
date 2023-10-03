#pragma once

#include "instruction.h"
#include "mem_accessor.h"

extern "C" {
    typedef struct ZydisDecoder_ ZydisDecoder;
    typedef struct ZydisFormatter_ ZydisFormatter;
    typedef struct ZydisDecodedOperand_ ZydisDecodedOperand;
    typedef struct ZydisDecodedInstruction_ ZydisDecodedInstruction;
}

namespace dyno {
	typedef std::unordered_map<uintptr_t, insts_t> branch_map_t;

	class ZydisDisassembler {
	public:
		explicit ZydisDisassembler(Mode mode);
		virtual ~ZydisDisassembler();

		insts_t disassemble(uintptr_t firstInstruction, uintptr_t start, uintptr_t end, const MemAccessor& accessor);

		// TODO: Move to accessor
		static void writeEncoding(const insts_t& instructions, const MemAccessor& accessor) {
			for (const auto& inst : instructions)
				writeEncoding(inst, accessor);
		}

		/**Write the raw bytes of the given instruction into the memory specified by the
		* instruction's address. If the address value of the instruction has been changed
		* since the time it was decoded this will copy the instruction to a new memory address.
		* This will not automatically do any code relocation, all relocation logic should
		* first modify the byte array, and then call write encoding, proper order to relocate
		* an instruction should be disasm instructions -> set relative/absolute displacement() ->
		**/
		static void writeEncoding(const Instruction& instruction, const MemAccessor& accessor) {
			assert(instruction.size() <= instruction.getBytes().size());
			accessor.mem_copy(instruction.getAddress(), (uintptr_t)&instruction.getBytes()[0], instruction.size());
		}

		static bool isConditionalJump(const Instruction& instruction);

		static bool isFuncEnd(const Instruction& instruction, bool firstFunc = false);

		static bool isPadBytes(const Instruction& instruction) {
			// supports multi-byte nops
			return instruction.getMnemonic() == "nop";
		}

        void addToBranchMap(insts_t& insVec, const Instruction& inst);

		const branch_map_t& getBranchMap() const {
			return m_branchMap;
		}

		Mode getMode() const {
			return m_mode;
		}
		
	protected:
		bool getOpStr(ZydisDecodedInstruction* pInstruction, const ZydisDecodedOperand* decoded_operands, uintptr_t addr, std::string* pOpStrOut);
		static void setDisplacementFields(Instruction& inst, const ZydisDecodedInstruction* zydisInst, const ZydisDecodedOperand* operands) ;
		typename branch_map_t::mapped_type& updateBranchMap(uintptr_t key, const Instruction& new_val);

		// we use a void pointer here since we don't want forward declare the ZydisDecoder
		ZydisDecoder* m_decoder;
		ZydisFormatter* m_formatter;

		Mode m_mode;

		/* key = address of instruction pointed at (dest of jump). Value = set of unique instruction branching to dest
		   Must only hold entries from the last segment disassembled. I.E clear every new call to disassemble
		*/
		branch_map_t m_branchMap;
	};
}