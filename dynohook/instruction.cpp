#include "instruction.h"
#include "mem_accessor.h"

using namespace dyno;

Instruction::Instruction(
    const MemAccessor* accessor,
    uintptr_t address,
    Displacement displacement,
    uint8_t displacementOffset,
    bool isRelative,
    bool isIndirect,
    std::vector<uint8_t>&& bytes,
    std::string&& mnemonic,
    std::string&& opStr,
    Mode mode
) : m_accessor{accessor},
    m_address{address},
    m_displacement{displacement},
    m_dispOffset{displacementOffset},
    m_dispSize{0},
    m_isRelative{isRelative},
    m_isIndirect{isIndirect},
    m_isCalling{false},
    m_isBranching{false},
    m_hasDisplacement{false},
    m_hasImmediate{false},
    m_immediate{0},
    m_immediateSize{0},
    m_register{0},

    m_bytes{std::move(bytes)},
    m_mnemonic{std::move(mnemonic)},
    m_opStr{std::move(opStr)},

    m_uid{s_counter++},
    m_mode{mode} {
}

void Instruction::setDestination(uintptr_t dest) {
    if (!hasDisplacement())
        return;

    if (isDisplacementRelative()) {
        auto newRelativeDisp = calculateRelativeDisplacement<intptr_t>(
            getAddress(),
            dest,
            (uint8_t)size()
        );

        setRelativeDisplacement(newRelativeDisp);
        return;
    }
    setAbsoluteDisplacement(dest);
}

uintptr_t Instruction::getDestination() const {
    uintptr_t dest = isDisplacementRelative() ? getRelativeDestination() : getAbsoluteDestination();

    // ff 25 00 00 00 00 goes from jmp qword ptr [rip + 0] to jmp word ptr [rip + 0] on x64 -> x86
    if (m_isIndirect) {
        size_t read = 0;
        if (m_mode == Mode::x64) {
            // *(uint64_t*)dest;
            m_accessor->safe_mem_read(dest, (uintptr_t)&dest, sizeof(uint64_t), read);
        } else {
            // *(uint32_t*)dest;
            m_accessor->safe_mem_read(dest, (uintptr_t)&dest, sizeof(uint32_t), read);
        }
    }
    return dest;
}

void Instruction::setAbsoluteDisplacement(uintptr_t displacement) {
    /**Update our class' book-keeping of this stuff and then modify the byte array.
    * This doesn't actually write the changes to the executeable code, it writes to our
    * copy of the bytes**/
    m_displacement.Absolute = displacement;
    m_isRelative = false;
    m_hasDisplacement = true;

    const auto dispSz = (uint32_t)(size() - getDisplacementOffset());
    if (((uint32_t)getDisplacementOffset()) + dispSz > m_bytes.size() || dispSz > sizeof(m_displacement.Absolute)) {
        return;
    }

    assert(((uint32_t)getDisplacementOffset()) + dispSz <= m_bytes.size() && dispSz <= sizeof(m_displacement.Absolute));
    std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Absolute, dispSz);
}

void Instruction::setRelativeDisplacement(intptr_t displacement) {
    /**Update our class' book-keeping of this stuff and then modify the byte array.
     * This doesn't actually write the changes to the executable code, it writes to our
     * copy of the bytes**/
    m_displacement.Relative = displacement;
    m_isRelative = true;
    m_hasDisplacement = true;

    assert((size_t)m_dispOffset + m_dispSize <= m_bytes.size() && m_dispSize <= sizeof(m_displacement.Relative));
    std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Relative, m_dispSize);
}

bool Instruction::startsWithDisplacement() const {
    if (getOperandTypes().empty()) {
        return false;
    }

    return getOperandTypes().front() == Instruction::OperandType::Displacement;
}