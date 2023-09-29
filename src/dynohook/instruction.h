#pragma once

#include "enums.h"
#include "mem_accessor.h"

#include <Zydis/Generated/EnumRegister.h>

namespace dyno {
    class Instruction {
    public:
        union Displacement {
            int64_t  Relative;
            uint64_t Absolute;
        };

        enum class OperandType : uint8_t {
            Displacement,
            Register,
            Immediate,
        };

        Instruction(uint64_t address,
                    Displacement displacement,
                    uint8_t displacementOffset,
                    bool isRelative,
                    bool isIndirect,
                    std::vector<uint8_t>&& bytes,
                    std::string&& mnemonic,
                    std::string&& opStr,
                    Mode mode) :
                m_address{address},
                m_displacement{displacement},
                m_dispOffset{displacementOffset},
                m_dispSize{0},
                m_isRelative{isRelative},
                m_isIndirect{isIndirect},
                m_hasDisplacement{false},
                m_hasImmediate{false},
                m_immediate{0},
                m_immediateSize{0},
                m_register{ZydisRegister::ZYDIS_REGISTER_NONE},

                m_bytes{std::move(bytes)},
                m_mnemonic{std::move(mnemonic)},
                m_opStr{std::move(opStr)},

                m_uid{m_counter++},
                m_mode{mode} {
        }

        uint64_t getAbsoluteDestination() const {
            return m_displacement.Absolute;
        }

        uint64_t getRelativeDestination() const {
            return m_address + m_displacement.Relative + size();
        }

        /**Get the address of where the instruction points if it's a branching instruction
        * @Notes: Handles eip/rip & immediate branches correctly
        * **/
        uint64_t getDestination() const {
            uint64_t dest = isDisplacementRelative() ? getRelativeDestination() : getAbsoluteDestination();

            // ff 25 00 00 00 00 goes from jmp qword ptr [rip + 0] to jmp word ptr [rip + 0] on x64 -> x86
            if (m_isIndirect) {
                size_t read = 0;
                if (m_mode == Mode::x64) {
                    // *(uint64_t*)dest;
                    m_accessor.safe_mem_read(dest, (uint64_t)&dest, sizeof(uint64_t), read);
                } else {
                    // *(uint32_t*)dest;
                    m_accessor.safe_mem_read(dest, (uint64_t)&dest, sizeof(uint32_t), read);
                }
            }
            return dest;
        }

        void setDestination(uint64_t dest) {
            if (!hasDisplacement())
                return;

            if (isDisplacementRelative()) {
                auto newRelativeDisp = calculateRelativeDisplacement<int64_t>(
                        getAddress(),
                        dest,
                        (uint8_t)size()
                );

                setRelativeDisplacement(newRelativeDisp);
                return;
            }
            setAbsoluteDisplacement(dest);
        }

        /**Get the address of the instruction in memory**/
        uint64_t getAddress() const {
            return m_address;
        }

        /**Set a new address of the instruction in memory
        @Notes: Doesn't move the instruction, marks it for move on writeEncoding and relocates if appropriate**/
        void setAddress(uint64_t address) {
            m_address = address;
        }

        /**Get the displacement from current address**/
        Displacement getDisplacement() const {
            return m_displacement;
        }

        /**Set where in the instruction bytes the offset is encoded**/
        void setDisplacementOffset(uint8_t offset) {
            m_dispOffset = offset;
        }

        void setBranching(const bool status) {
            m_isBranching = status;
        }

        void setCalling(const bool isCalling) {
            m_isCalling = isCalling;
        }

        /**Get the offset into the instruction bytes where displacement is encoded**/
        uint8_t getDisplacementOffset() const {
            return m_dispOffset;
        }

        /**Check if displacement is relative to eip/rip**/
        bool isDisplacementRelative() const {
            return m_isRelative;
        }

        /**Check if the instruction is a type with valid displacement**/
        bool hasDisplacement() const {
            return m_hasDisplacement;
        }

        void setHasDisplacement(bool hasDisplacement) {
            m_hasDisplacement = hasDisplacement;
        }

        bool isBranching() const {
            if (m_isBranching && m_isRelative) {
                assert(m_hasDisplacement);
            }
            return m_isBranching;
        }

        bool isCalling() const {
            return m_isCalling;
        }

        bool isIndirect() const {
            return m_isIndirect;
        }

        const std::vector<uint8_t>& getBytes() const {
            return m_bytes;
        }

        /**Get short symbol name of instruction**/
        const std::string& getMnemonic() const {
            return m_mnemonic;
        }

        /**Get symbol name and parameters**/
        std::string getFullName() const {
            return m_mnemonic + " " + m_opStr;
        }

        /** Displacement size in bytes **/
        void setDisplacementSize(uint8_t size){
            m_dispSize = size;
        }

        size_t getDispSize() const {
            return m_dispSize;
        }

        size_t size() const {
            return m_bytes.size();
        }

        void setRelativeDisplacement(const int64_t displacement) {
            /**Update our class' book-keeping of this stuff and then modify the byte array.
             * This doesn't actually write the changes to the executable code, it writes to our
             * copy of the bytes**/
            m_displacement.Relative = displacement;
            m_isRelative = true;
            m_hasDisplacement = true;

            assert((size_t)m_dispOffset + m_dispSize <= m_bytes.size() && m_dispSize <= sizeof(m_displacement.Relative));
            std::memcpy(&m_bytes[getDisplacementOffset()], &m_displacement.Relative, m_dispSize);
        }

        void setAbsoluteDisplacement(uint64_t displacement) {
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

        uint32_t getUID() const {
            return m_uid;
        }

        template<typename T>
        static T calculateRelativeDisplacement(uint64_t from, uint64_t to, uint8_t insSize) {
            if (to < from)
                return (T)(0 - (from - to) - insSize);
            return (T)(to - (from + insSize));
        }

        void setIndirect(const bool isIndirect) {
            m_isIndirect = isIndirect;
        }

        void setImmediate(uint64_t immediate){
            m_hasImmediate = true;
            m_immediate = immediate;
        }

        bool hasImmediate() const {
            return m_hasImmediate;
        }

        uint64_t getImmediate() const {
            return m_immediate;
        }

        uint8_t getImmediateSize() const {
            return m_immediateSize;
        }

        void setImmediateSize(uint8_t size) {
            m_immediateSize = size;
        }

        void setRegister(ZydisRegister reg){
            m_register = reg;
        }

        ZydisRegister getRegister() const {
            return m_register;
        }

        bool hasRegister() const {
            return m_register != ZYDIS_REGISTER_NONE;
        }

        void addOperandType(OperandType type){
            m_operands.emplace_back(type);
        }

        const std::vector<OperandType>& getOperandTypes() const {
            return m_operands;
        }

        bool startsWithDisplacement() const {
            if(getOperandTypes().empty()){
                return false;
            }

            return getOperandTypes().front() == Instruction::OperandType::Displacement;
        }

        // This is kind of lazy, should probably make be a non-static member for each instance
        static void overrideMemAccessor(MemAccessor accessor) {
            m_accessor = accessor;
        }
		
    private:
        ZydisRegister m_register;        // Register operand when displacement is present
        bool          m_isIndirect;      // Does this instruction get its destination via an indirect mem read (ff 25 ... jmp [jmp_dest]) (only filled for jmps / calls)
        bool          m_isCalling;       // Does this instruction is of a CALL type.
        bool		  m_isBranching;     // Does this instruction jmp/call or otherwise change control flow
        bool          m_isRelative;      // Does the displacement need to be added to the address to retrieve where it points too?
        bool          m_hasDisplacement; // Does this instruction have the displacement fields filled (only rip/eip relative types are filled)
        bool          m_hasImmediate;    // Does this instruction have the immediate field filled?
        Displacement  m_displacement;    // Where an instruction points too (valid for jmp + call types, and RIP relative MEM types)

        uint64_t      m_address;         // Address the instruction is at
        uint64_t      m_immediate;       // Immediate op
        uint8_t       m_immediateSize;   // Immediate size, in bytes
        uint8_t       m_dispOffset;      // Offset into the byte array where displacement is encoded
        uint8_t       m_dispSize;        // Size of the displacement, in bytes

        std::vector<uint8_t> m_bytes;    // All the raw bytes of this instruction
        std::vector<OperandType> m_operands; // Types of all instruction operands
        std::string m_mnemonic;
        std::string m_opStr;

        Mode m_mode;

        uint32_t m_uid;

		inline static uint32_t m_counter = 0;
        inline static MemAccessor m_accessor;
    };
    static_assert(std::is_nothrow_move_constructible<Instruction>::value, "dyno::Instruction should be noexcept move constructable");

    typedef std::vector<Instruction> insts_t;

    inline bool operator==(const Instruction& lhs, const Instruction& rhs) {
        return lhs.getUID() == rhs.getUID();
    }
    inline std::ostream& operator<<(std::ostream& os, const Instruction& obj) {
        std::stringstream byteStream;
        for (std::size_t i = 0; i < obj.size(); i++)
            byteStream << std::hex << std::setfill('0') << std::setw(2) << (unsigned)obj.getBytes()[i] << " ";

        os << std::hex << obj.getAddress() << " [" << obj.size() << "]: ";
        os << std::setfill(' ') << std::setw(40) << std::left << byteStream.str();
        os << obj.getFullName();

        if (obj.hasDisplacement() && obj.isDisplacementRelative())
            os << " -> " << obj.getDestination();
        os << std::dec;
        return os;
    }

    inline uint16_t calcInstsSz(const insts_t& insts) {
        uint16_t sz = 0;
        for (const auto& ins : insts)
            sz += (uint16_t)ins.size();
        return sz;
    }

    template<typename T>
    std::string instsToStr(const T& container) {
        std::stringstream ss;
        printInsts(ss, container);
        return ss.str();
    }

    template <typename T>
    inline std::ostream& printInsts(std::ostream& out, const T& container) {
        for (auto ii = container.cbegin(); ii != container.cend(); ++ii) {
            out << *ii << std::endl;
        }
        return out;
    }

    inline std::ostream& operator<<(std::ostream& os, const std::vector<Instruction>& v) { return printInsts(os, v); }

    /**Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
     * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.**/
    inline insts_t makex64PreferredJump(uint64_t address, uint64_t destination) {
        Instruction::Displacement zeroDisp = { 0 };
        uint64_t                       curInstAddress = address;

        std::vector<uint8_t> raxBytes = { 0x50 };
        Instruction pushRax{curInstAddress,
                            zeroDisp,
                            0,
                            false,
                            false,
                            std::move(raxBytes),
                            "push",
                            "rax", Mode::x64};
        curInstAddress += pushRax.size();

        std::stringstream ss;
        ss << std::hex << destination;

        std::vector<uint8_t> movRaxBytes;
        movRaxBytes.resize(10);
        movRaxBytes[0] = 0x48;
        movRaxBytes[1] = 0xB8;
        memcpy(&movRaxBytes[2], &destination, 8);

        Instruction movRax{curInstAddress, zeroDisp, 0, false, false,
                           std::move(movRaxBytes), "mov", "rax, " + ss.str(), Mode::x64};
        curInstAddress += movRax.size();

        std::vector<uint8_t> xchgBytes = { 0x48, 0x87, 0x04, 0x24 };
        Instruction xchgRspRax{curInstAddress, zeroDisp, 0, false, false,
                               std::move(xchgBytes), "xchg", "QWORD PTR [rsp],rax", Mode::x64};
        curInstAddress += xchgRspRax.size();

        std::vector<uint8_t> retBytes = { 0xC3 };
        Instruction ret{curInstAddress, zeroDisp, 0, false, false,
                        std::move(retBytes, "ret", "", Mode::x64};

        return { pushRax, movRax, xchgRspRax, ret };
    }

    /**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
     * destHolder should point to the memory location that *CONTAINS* the address to be jumped to.
     * Destination should be the value that is written into destHolder, and be the address of where
     * the jmp should land.**/
    inline insts_t makex64MinimumJump(uint64_t address, uint64_t destination, uint64_t destHolder) {
        Instruction::Displacement disp{ 0 };
        disp.Relative = Instruction::calculateRelativeDisplacement<int32_t>(address, destHolder, 6);

        std::vector<uint8_t> destBytes;
        destBytes.resize(8);
        memcpy(destBytes.data(), &destination, 8);
        Instruction specialDest{ destHolder, disp, 0, false, false, std::move(destBytes), "dest holder", "", Mode::x64 };

        std::vector<uint8_t> bytes;
        bytes.resize(6);
        bytes[0] = 0xFF;
        bytes[1] = 0x25;
        memcpy(&bytes[2], &disp.Relative, 4);

        std::stringstream ss;
        ss << std::hex << "[" << destHolder << "] ->" << destination;

        return { Instruction{address, disp, 2, true, true, std::move(bytes), "jmp", ss.str(), Mode::x64},  specialDest };
    }

    inline insts_t makex86Jmp(uint64_t address, uint64_t destination) {
        Instruction::Displacement disp{ 0 };
        disp.Relative = Instruction::calculateRelativeDisplacement<int32_t>(address, destination, 5);

        std::vector<uint8_t> bytes(5);
        bytes[0] = 0xE9;
        memcpy(&bytes[1], &disp.Relative, 4);

        return { Instruction{address, disp, 1, true, false, std::move(bytes), "jmp", int_to_hex(destination), Mode::x86} };
    }

    inline insts_t makeAgnosticJmp(uint64_t address, uint64_t destination) {
#if DYNO_ARCH_X86 == 32
            return makex86Jmp(address, destination);
#elif DYNO_ARCH_X86 == 64
            return makex64PreferredJump(address, destination);
#endif
    }

    inline insts_t makex64DestHolder(uint64_t destination, uint64_t destHolder) {
        std::vector<uint8_t> destBytes;
        destBytes.resize(8);
        memcpy(destBytes.data(), &destination, 8);
        return insts_t{ Instruction {destHolder, Instruction::Displacement{0}, 0, false, false, std::move(destBytes), "dest holder", "", Mode::x64} };
    }
}