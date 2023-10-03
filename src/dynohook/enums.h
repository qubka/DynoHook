#pragma once

namespace dyno {
	/**
	 * Used by detours class only. This doesn't live in instruction because it
	 * only makes sense for specific jump instructions (perhaps re-factor instruction
	 * to store inst. specific stuff when needed?). There are two classes of information for jumps
	 * 1) how displacement is encoded, either relative to I.P. or Absolute
	 * 2) where the jmp points, either absolutely to the destination or to a memory loc. that then points to the final dest.
	 *
	 * The first information is stored internal to the PLH::Instruction object. The second is this enum class that you
	 * tack on via a pair or tuple when you need to transfer that knowledge.
	 */
	enum class JmpType : uint8_t {
		Absolute,
		Indirect
	};

	enum class Mode : uint8_t {
		x86,
		x64
	};

    // unsafe enum by design to allow binary OR
    enum ProtFlag : uint8_t {
        UNSET = 0, // value means this give no information about protection state (un-read)
        X = 1 << 1,
        R = 1 << 2,
        W = 1 << 3,
        S = 1 << 4,
        P = 1 << 5,
        N = 1 << 6, // value equaling the linux flag PROT_UNSET (read the prot, and the prot is unset)
        RWX = R | W | X
    };
}

inline dyno::ProtFlag operator|(dyno::ProtFlag lhs, dyno::ProtFlag rhs) {
    using underlying = typename std::underlying_type<dyno::ProtFlag>::type;
    return static_cast<dyno::ProtFlag> (
        static_cast<underlying>(lhs) |
        static_cast<underlying>(rhs)
    );
}

inline bool operator&(dyno::ProtFlag lhs, dyno::ProtFlag rhs) {
    using underlying = typename std::underlying_type<dyno::ProtFlag>::type;
    return static_cast<underlying>(lhs) &
           static_cast<underlying>(rhs);
}