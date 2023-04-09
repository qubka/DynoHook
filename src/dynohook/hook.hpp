#pragma once

#include "registers.hpp"
#include "convention.hpp"

#include "asmjit/asmjit.h"

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
            return *(T*) m_pCallingConvention->getArgumentPtr(index, m_Registers);
        }

        template<class T>
        void setArgument(size_t index, T value) {
            void* argumentPtr = m_pCallingConvention->getArgumentPtr(index, m_Registers);
            *(T*) argumentPtr = value;
            m_pCallingConvention->onArgumentPtrChanged(index, m_Registers, argumentPtr);
        }

        template<class T>
        T getReturnValue() const {
            return *(T*) m_pCallingConvention->getReturnPtr(m_Registers);
        }

        template<class T>
        void setReturnValue(T value) {
            void* retunrPtr = m_pCallingConvention->getReturnPtr(m_Registers);
            *(T*) retunrPtr = value;
            m_pCallingConvention->onReturnPtrChanged(m_Registers, retunrPtr);
        }

    private:
        void createBridge() const;
        void createPostCallback() const;
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
        std::map<HookType, std::vector<HookHandler*>> m_Handlers;

        // Address of the original function
        void* m_pFunc;

        // Instructions of the original function
        std::vector<uint8_t> m_OriginalInstructions;

        // Interface if the calling convention
        ICallingConvention* m_pCallingConvention;

        // Address of the bridge
        void* m_pBridge;

        // Address of the trampoline
        void* m_pTrampoline;

        // New return address
        void* m_pNewRetAddr;

        // Save the last return action of the pre HookHandler for use in the post handler.
        std::vector<ReturnAction> m_LastPreReturnAction;

        // Register storage
        Registers m_Registers;
        Registers m_ScratchRegisters;

        //
        std::map<void*, std::vector<void*>> m_RetAddr;

        // Runtime designed for JIT
        asmjit::JitRuntime& m_Jit;
    };
}