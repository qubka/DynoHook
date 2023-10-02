#pragma once

#include "enums.h"
#include "instruction.h"

#define MEMORY_ROUND(_numToRound_, _multiple_) \
    (_numToRound_ & (((size_t)-1) ^ (_multiple_ - 1)))

// Round _numToRound_ to the next higher _multiple_
#define MEMORY_ROUND_UP(_numToRound_, _multiple_) \
    ((_numToRound_ + (_multiple_ - 1)) & (((size_t)-1) ^ (_multiple_ - 1)))

namespace dyno {
	/// Overriding these routines can allow cross-process/cross-arch hooks
	class MemAccessor {
	public:
		virtual ~MemAccessor() = default;

		/**
		 * Defines a memory read/write routine that may fail ungracefully. It's expected
		 * this library will only ever use this routine in cases that are expected to succeed.
		**/
        virtual bool mem_copy(uint64_t dest, uint64_t src, uint64_t size) const;

		/**
		 * Defines a memory write routine that will not throw exceptions, and can handle potential
		 * writes to NO_ACCESS or otherwise innaccessible memory pages. Defaults to writeprocessmemory.
		 * Must fail gracefully
		**/
        virtual bool safe_mem_write(uint64_t dest, uint64_t src, uint64_t size, size_t& written) const noexcept;

		/**
		 * Defines a memory read routine that will not throw exceptions, and can handle potential
		 * reads from NO_ACCESS or otherwise innaccessible memory pages. Defaults to readprocessmemory.
		 * Must fail gracefully
		**/
        virtual bool safe_mem_read(uint64_t src, uint64_t dest, uint64_t size, size_t& read) const noexcept;

		virtual ProtFlag mem_protect(uint64_t dest, uint64_t size, ProtFlag newProtection, bool& status) const;



        /**Write a 25 byte absolute jump. This is preferred since it doesn't require an indirect memory holder.
         * We first sub rsp by 128 bytes to avoid the red-zone stack space. This is specific to unix only afaik.**/
        insts_t makex64PreferredJump(uint64_t address, uint64_t destination);

        /**Write an indirect style 6byte jump. Address is where the jmp instruction will be located, and
         * destHolder should point to the memory location that *CONTAINS* the address to be jumped to.
         * Destination should be the value that is written into destHolder, and be the address of where
         * the jmp should land.**/
        insts_t makex64MinimumJump(uint64_t address, uint64_t destination, uint64_t destHolder);
        insts_t makex86Jmp(uint64_t address, uint64_t destination);
        insts_t makeAgnosticJmp(uint64_t address, uint64_t destination);

        insts_t makex64DestHolder(uint64_t destination, uint64_t destHolder);
	};
}