#pragma once

#include "mem_accessor.h"
#include "_hook.h"
#include <asmjit/asmjit.h>

namespace dyno {
    /**
     * Creates and manages hooks at the beginning of a function.
     * This hooking method requires knowledge of parameters and calling convention of the target function.
     */
    class Hook : public MemAccessor, public IHook {
    public:
        explicit Hook(const ConvFunc& convention);
        ~Hook() override = default;
        DYNO_NONCOPYABLE(Hook);

        bool addCallback(CallbackType type, CallbackHandler handler) override;
        bool removeCallback(CallbackType type, CallbackHandler handler) override;
        bool isCallbackRegistered(CallbackType type, CallbackHandler handler) const override;
        bool areCallbacksRegistered() const override;

        bool rehook() override {
            return true;
        }

        bool setHooked(bool state) override {
            if (m_hooked == state)
                return true;

            return state ? hook() : unhook();
        }

        bool isHooked() const override {
            return m_hooked;
        }

        const uintptr_t& getBridge() const {
            return m_fnBridge;
        }

    protected:
        bool createBridge();
        bool createPostCallback();

        ICallingConvention& getCallingConvention() override {
            return *m_callingConvention;
        }
        Registers& getRegisters() override {
            return m_registers;
        }

    private:
        typedef asmjit::x86::Assembler Assembler;

        void writeModifyReturnAddress(Assembler& a);
        void writeCallHandler(Assembler& a, CallbackType type) const;
        void writeSaveRegisters(Assembler& a, CallbackType type) const;
        void writeRestoreRegisters(Assembler& a, CallbackType type) const;
        void writeSaveScratchRegisters(Assembler& a) const;
        void writeRestoreScratchRegisters(Assembler& a) const;
        void writeRegToMem(Assembler& a, const Register& reg, CallbackType type = CallbackType::Pre) const;
        void writeMemToReg(Assembler& a, const Register& reg, CallbackType type = CallbackType::Pre) const;

DYNO_OPTS_OFF
        DYNO_NOINLINE ReturnAction DYNO_CDECL callbackHandler(CallbackType type);
        DYNO_NOINLINE void* DYNO_CDECL getReturnAddress(void* stackPtr);
        DYNO_NOINLINE void DYNO_CDECL setReturnAddress(void* retAddr, void* stackPtr);
DYNO_OPTS_ON

    protected:
        asmjit::JitRuntime m_asmjit_rt;

        // address storage
        uintptr_t m_fnBridge{ 0 };
        uintptr_t m_newRetAddr{ 0 };

        // interface if the calling convention
        std::unique_ptr<ICallingConvention> m_callingConvention;

        // register storage
        Registers m_registers;
        Registers m_scratchRegisters;

        // save the last return action of the pre callbackHander for use in the post handler.
        std::vector<ReturnAction> m_lastPreReturnAction;

        // individual return's stack for stack pointers
        std::unordered_map<void*, std::vector<void*>> m_retAddr;

        // callbacks list
        std::unordered_map<CallbackType, std::vector<CallbackHandler>> m_handlers;

        bool m_hooked{ false };
    };
}