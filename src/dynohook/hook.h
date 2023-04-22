#pragma once

#include "registers.h"
#include "convention.h"

namespace asmjit { inline namespace _abi_1_10 {
        class JitRuntime;
        namespace x86 {
            class Assembler;
        }
    }
}

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
        friend class VHook;
    public:
        /**
         * @brief Creates a new function hook.
         * @param jit The jit runtime object.
         * @param func The address of the function to hook.
         * @param convention The calling convention of <func>.
         */
        Hook(asmjit::JitRuntime* jit, CallingConvention* convention);
        virtual ~Hook();
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

    protected:
        bool createBridge(void* trampoline);
        bool createPostCallback();

    private:
        typedef asmjit::x86::Assembler Assembler;

        void writeModifyReturnAddress(Assembler& a);
        void writeCallHandler(Assembler& a, HookType hookType) const;
        void writeSaveRegisters(Assembler& a, HookType hookType) const;
        void writeRestoreRegisters(Assembler& a, HookType hookType) const;
        void writeSaveScratchRegisters(Assembler& a) const;
        void writeRestoreScratchRegisters(Assembler& a) const;
        void writeRegToMem(Assembler& a, const Register& reg, HookType hookType = HookType::Pre) const;
        void writeMemToReg(Assembler& a, const Register& reg, HookType hookType = HookType::Pre) const;

#ifdef DYNO_PLATFORM_MSVC
#pragma optimize ("", off)
#elif DYNO_PLATFORM_GCC_COMPATIBLE
#pragma OPT push_options
#pragma OPT optimize ("O0")
#endif
        DYNO_NOINLINE ReturnAction DYNO_CDECL hookHandler(HookType hookType);
        DYNO_NOINLINE void* DYNO_CDECL getReturnAddress(void* stackPtr);
        DYNO_NOINLINE void DYNO_CDECL setReturnAddress(void* retAddr, void* stackPtr);
#ifdef DYNO_PLATFORM_MSVC
#pragma optimize ("", on)
#elif DYNO_PLATFORM_GCC_COMPATIBLE
#pragma OPT pop_options
#endif

    protected:
        // runtime designed for JIT - it holds relocated functions and controls their lifetime
        asmjit::JitRuntime* m_jit;

        // interface if the calling convention
        CallingConvention* m_callingConvention;

        // address of the bridge
        void* m_bridge;

        // new return address
        void* m_newRetAddr;

        // register storage
        Registers m_registers;
        Registers m_scratchRegisters;

        // save the last return action of the pre HookHandler for use in the post handler.
        std::vector<ReturnAction> m_lastPreReturnAction;

        // individual return's stack for stack pointers
        std::map<void*, std::vector<void*>> m_retAddr;

        // callbacks list
        std::map<HookType, std::vector<HookHandler*>> m_handlers;
    };
}