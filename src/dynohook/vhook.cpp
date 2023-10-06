#pragma once

#include "hook.h"

namespace dyno {
    class VHook final : public Hook {
    public:
        VHook(uintptr_t fnAddress, const ConvFunc& convention) : Hook{convention}, m_fnAddress{fnAddress} {
			assert(fnAddress != 0 && "Function address cannot be null");
		}

		~VHook() override {
			if (m_hooked) {
				unhook();
			}
		}
		
		bool hook() override;
		bool unhook() override;

		HookMode getMode() const override {
			return HookMode::VTableSwap;
		}

        uintptr_t getAddress() const override {
            return m_fnAddress;
        }

    private:
        // address of the original function
        uintptr_t m_fnAddress;
    };
}