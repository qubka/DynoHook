#include "detour.h"

#include <cmath>

using namespace dyno;

Detour::Detour(uintptr_t fnAddress, const ConvFunc& convention, Mode mode) : Hook{convention}, m_fnAddress{fnAddress}, m_disasm{mode} {
    assert(fnAddress != 0 && "Function address cannot be null");
}

Detour::~Detour() override {
    if (m_hooked) {
        unhook();
    }
}
uint8_t Detour::getMaxDepth() const {
    return m_maxDepth;
}

void Detour::setMaxDepth(uint8_t maxDepth) {
    assert(maxDepth > 0 && "Max depth must be positive");
    m_maxDepth = maxDepth;
}

void Detour::setIsFollowCallOnFnAddress(bool value) {
    m_isFollowCallOnFnAddress = value;
}

std::optional<insts_t> Detour::calcNearestSz(
        const insts_t& functionInsts,
        uintptr_t prolOvrwStartOffset,
        uintptr_t& prolOvrwEndOffset
) {
    uintptr_t prolLen = 0;
    insts_t instructionsInRange;

    // count instructions until at least length needed or func end
    bool endHit = false;
    for (const auto& inst: functionInsts) {
        prolLen += inst.size();
        instructionsInRange.push_back(inst);

        // only safe to overwrite pad bytes once end is hit
        if (endHit && !ZydisDisassembler::isPadBytes(inst))
            break;

        if (ZydisDisassembler::isFuncEnd(inst))
            endHit = true;

        if (prolLen >= prolOvrwStartOffset)
            break;
    }

    prolOvrwEndOffset = prolLen;
    if (prolLen >= prolOvrwStartOffset) {
        return instructionsInRange;
    }

    return std::nullopt;
}

bool Detour::followJmp(insts_t& functionInsts, uint8_t curDepth) { // NOLINT(misc-no-recursion)
    if (functionInsts.empty()) {
        LOG_PRINT("Couldn't decompile instructions at followed jmp");
        return false;
    }

    if (curDepth >= m_maxDepth) {
        LOG_PRINT("Prologue jmp resolution hit max depth, prologue too deep");
        return false;
    }

    // not a branching instruction, no resolution needed
    if (!functionInsts.front().isBranching()) {
        return true;
    }

    if (!m_isFollowCallOnFnAddress) {
        LOG_PRINT("setting: Do NOT follow CALL on fnAddress");
        if (functionInsts.front().isCalling()) {
            LOG_PRINT("First assembly instruction is CALL");
            return true;
        }
    }

    // might be a mem type like jmp rax, not supported
    if (!functionInsts.front().hasDisplacement()) {
        LOG_PRINT("Branching instruction without displacement encountered");
        return false;
    }

    uintptr_t dest = functionInsts.front().getDestination();
    functionInsts = m_disasm.disassemble(dest, dest, dest + 100, *this);
    return followJmp(functionInsts, curDepth + 1); // recurse
}

bool Detour::expandProlSelfJmps(insts_t& prol, const insts_t& func, uintptr_t& minProlSz, uintptr_t& roundProlSz) {
    uintptr_t maxAddr = 0;
    const uintptr_t prolStart = prol.front().getAddress();
    const branch_map_t& branchMap = m_disasm.getBranchMap();
    for (size_t i = 0; i < prol.size(); i++) {
        auto inst = prol.at(i);

        // is there a jump pointing at the current instruction?
        if (branchMap.find(inst.getAddress()) == branchMap.end())
            continue;

        insts_t srcs = branchMap.at(inst.getAddress());

        for (const auto& src : srcs) {
            const uintptr_t srcEndAddr = src.getAddress() + src.size();
            if (srcEndAddr > maxAddr)
                maxAddr = srcEndAddr;
        }

        minProlSz = maxAddr - prolStart;

        // expand prol by one entry size, may fail if prol too small
        const auto prolOpt = calcNearestSz(func, minProlSz, roundProlSz);
        if (!prolOpt) {
            return false;
        }
        prol = *prolOpt; // False flag: LocalValueEscapesScope
    }

    return true;
}

void Detour::buildRelocationList(
        insts_t& prologue,
        uintptr_t roundProlSz,
        const intptr_t delta,
        insts_t& instsNeedingEntry,
        insts_t& instsNeedingReloc,
        insts_t& instsNeedingTranslation
) {
    assert(instsNeedingEntry.empty());
    assert(instsNeedingReloc.empty());
    assert(!prologue.empty());

    const uintptr_t prolStart = prologue.front().getAddress();

    for (auto& inst: prologue) {
        if (!inst.hasDisplacement()) {
            continue; // Skip instructions that don't have relative displacement
        }
        const auto dispSzBits = (uint8_t) inst.getDispSize() * 8;
        // 2^(bitSz-1) give max val, and -1 because signed ex (int8_t [-128, 127] = [-2^7, 2^7 - 1]
        const auto maxInstDisp = (uintptr_t) (std::pow(2, dispSzBits - 1) - 1.0);
        const auto absDelta = (uintptr_t) std::llabs(delta);

        // types that change control flow
        if (inst.isBranching() &&
            (inst.getDestination() < prolStart ||
             inst.getDestination() > prolStart + roundProlSz)) {

            //indirect-call always needs an entry (only a dest-holder)
            //its destination cannot be used for relocating since it is already dereferenced.(ref: inst.getDestination)
            if (inst.isCalling() && inst.isIndirect()) {
                instsNeedingEntry.push_back(inst);
            } else {
                // can inst just be re-encoded or do we need a tbl entry
                if (absDelta > maxInstDisp) {
                    instsNeedingEntry.push_back(inst);
                } else {
                    instsNeedingReloc.push_back(inst);
                }
            }
        }

        // data operations (duplicated because clearer)
        if (!inst.isBranching()) { // Can this happen on 32-bit?
            if (absDelta > maxInstDisp) {
                /*
                 * EX: 48 8d 0d 96 79 07 00    lea rcx, [rip + 0x77996]
                 * If instruction is moved beyond displacement field width
                 * we can't fix the displacement. Hence, we add it to the list of
                 * instructions that need to be translated to equivalent ones.
                 */
                instsNeedingTranslation.push_back(inst);
            } else {
                instsNeedingReloc.push_back(inst);
            }
        }
    }
}

bool Detour::unhook() {
    if (!m_hooked) {
        LOG_PRINT("Detour unhook failed: no hook present");
        return false;
    }

    MemProtector prot{m_fnAddress, calcInstsSz(m_originalInsts), ProtFlag::R | ProtFlag::W | ProtFlag::X, *this};
    writeEncoding(m_originalInsts);

    if (m_trampoline != NULL) {
        delete[](uint8_t*) m_trampoline;
        m_trampoline = NULL;
    }

    m_hooked = false;
    return true;
}

bool Detour::rehook() {
    MemProtector prot{m_fnAddress, m_hookSize, ProtFlag::RWX, *this};
    writeEncoding(m_hookInsts);

    // Nop the space between jmp and end of prologue
    if (m_hookSize < m_nopProlOffset) {
        LOG_PRINT("hook size must not be larger than nop prologue offset");
        return false;
    }

    const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
    writeEncoding(nops);

    return true;
}

insts_t Detour::make_nops(uintptr_t address, uint16_t size) const {
    if (size < 1) {
        return {};
    }

    const uint8_t max_nop_size = 9;

    const auto make_nop_inst = [&](std::vector<uint8_t>&& bytes) {
        return Instruction{this, address, {0}, 0, false, false, std::move(bytes), "nop", "", getArchType()};
    };

    // lambda updates the address for each created instruction
    const auto make_nop = [&](uint8_t nop_size) {
        assert(nop_size <= max_nop_size);

        // https://stackoverflow.com/questions/25545470/long-multi-byte-nops-commonly-understood-macros-or-other-notation
        switch (nop_size) {
            case 1: return make_nop_inst({0x90});
            case 2: return make_nop_inst({0x66, 0x90});
            case 3: return make_nop_inst({0x0F, 0x1F, 0x00});
            case 4: return make_nop_inst({0x0F, 0x1F, 0x40, 0x00});
            case 5: return make_nop_inst({0x0F, 0x1F, 0x44, 0x00, 0x00});
            case 6: return make_nop_inst({0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00});
            case 7: return make_nop_inst({0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00});
            case 8: return make_nop_inst({0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
            default:return make_nop_inst({0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00});
        }
    };

    insts_t nops;

    auto max_nop_count = (int) (size / max_nop_size);
    auto remainder_nop_size = (uint8_t) (size % max_nop_size);

    for (int i = 0; i < max_nop_count; i++) {
        nops.emplace_back(make_nop(max_nop_size));
        address += max_nop_size;
    }

    if (remainder_nop_size) {
        nops.emplace_back(make_nop(remainder_nop_size));
    }

    return nops;
}