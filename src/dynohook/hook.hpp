#pragma once

#include "registers.hpp"
#include "convention.hpp"

#include <asmjit/asmjit.h>

namespace dyno {
    enum class HookType : bool {
        Pre,  // callback will be executed before the original function
        Post  // callback will be executed after the original function
    };

    enum class ReturnAction : uint8_t {
        Ignored,  // handler didn't take any action
        Handled,  // we did something, but real function should still be called
        Override, // call real function, but use my return value
        Supercede // skip real function; use my return value
    };

    class Hook;
    typedef ReturnAction (*HookHandler)(HookType, Hook&);

    class Hook {
    private:
        friend class HookManager;

        /**
         * @brief Creates a new function hook.
         * @param jit The jit runtime object.
         * @param func The address of the function to hook.
         * @param convention The calling convention of <func>.
         */
        Hook(asmjit::JitRuntime& jit, void* func, ICallingConvention* convention);
        ~Hook();

    public:
        NONCOPYABLE(Hook);

        /**
         * @brief Adds a hook handler to the hook.
         * @param hookType The hook type.
         * @param func The hook handler that should be added.
         */
        void addCallback(HookType hookType, HookHandler* func);

        /**
         * @brief Removes a hook handler to the hook.
         * @param hookType The hook type.
         * @param func The hook handler that should be removed.
         */
        void removeCallback(HookType hookType, HookHandler* func);

        /**
         * @brief Checks if a hook handler is already added.
         * @param hookType The hook type.
         * @param func The hook handler that should be checked.
         * @return
         */
        bool isCallbackRegistered(HookType hookType, HookHandler* func) const;

        /**
         * @brief Checks if there are any hook handlers added to this hook.
         * @return
         */
        bool areCallbacksRegistered() const;

        template<class T>
        T getArgument(size_t index) const {
            return *(T*) m_callingConvention->getArgumentPtr(index, m_registers);
        }

        template<class T>
        void setArgument(size_t index, T value) {
            void* argumentPtr = m_callingConvention->getArgumentPtr(index, m_registers);
            *(T*) argumentPtr = value;
            m_callingConvention->onArgumentPtrChanged(index, m_registers, argumentPtr);
        }

        template<class T>
        T getReturnValue() const {
            return *(T*) m_callingConvention->getReturnPtr(m_registers);
        }

        template<class T>
        void setReturnValue(T value) {
            void* retunrPtr = m_callingConvention->getReturnPtr(m_registers);
            *(T*) retunrPtr = value;
            m_callingConvention->onReturnPtrChanged(m_registers, retunrPtr);
        }

    private:
        bool createTrampoline(bool restrictedRelocation);
        bool createBridge() const;
        bool createPostCallback() const;
        std::vector<RegisterType> createScratchRegisters() const;

        typedef asmjit::x86::Assembler Assembler;

        void writeModifyReturnAddress(Assembler& a) const;
        void writeCallHandler(Assembler& a, HookType hookType) const;
        void writeSaveRegisters(Assembler& a, HookType hookType) const;
        void writeRestoreRegisters(Assembler& a, HookType hookType) const;
        void writeSaveScratchRegisters(Assembler& a) const;
        void writeRestoreScratchRegisters(Assembler& a) const;
        void writeRegToMem(Assembler& a, const Register& reg, HookType hookType = HookType::Pre) const; // hookType not used on x64
        void writeMemToReg(Assembler& a, const Register& reg, HookType hookType = HookType::Pre) const; // hookType not used on x64

        ASMJIT_NOINLINE ReturnAction ASMJIT_CDECL hookHandler(HookType hookType);
        ASMJIT_NOINLINE void* ASMJIT_CDECL getReturnAddress(void* stackPtr);
        ASMJIT_NOINLINE void ASMJIT_CDECL setReturnAddress(void* retAddr, void* stackPtr);

    public:
        // Runtime designed for JIT
        asmjit::JitRuntime& m_jit;

        // Address of the original function
        void* m_func;

        // Interface if the calling convention
        ICallingConvention* m_callingConvention;

        // Address of the bridge
        void* m_bridge;

        // Address of the trampoline
        void* m_trampoline;

        // New return address
        void* m_newRetAddr;

        // Instructions of the original function
        int8_t* m_originalBytes;

        size_t m_hookLength;

        // Register storage
        Registers m_registers;
        Registers m_scratchRegisters;

        // Save the last return action of the pre HookHandler for use in the post handler.
        std::vector<ReturnAction> m_lastPreReturnAction;

        //
        std::map<void*, std::vector<void*>> m_retAddr;

        std::map<HookType, std::vector<HookHandler*>> m_handlers;
    };
}